use crate::{
    auth::{LABEL, PublicKeys, Verifier},
    capsule::{DatagramReceiver, DatagramSender, MAX_UDP},
    config::{Origin, ServerConfig, idle_duration, read_limited, target_path, validate_target},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const NOT_FOUND: &[u8] = b"<!doctype html><title>Not Found</title><h1>Not Found</h1>\n";
const DEFAULT_PAGE: &[u8] = b"<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Watch the configuration and TLS material. Validate replacements before
/// shutting down old sessions; a revoked key cannot retain an old TLS tunnel.
/// The listening socket stays bound across reloads. Invalid updates retain the
/// last valid configuration and are retried, without logging credential data.
pub async fn serve_reloading(path: &std::path::Path, shutdown: CancellationToken) -> Result<()> {
    fn snapshot(path: &std::path::Path) -> Result<([u8; 32], ServerConfig, Arc<Server>)> {
        let contents = read_limited(path, 65_536)?;
        let config = ServerConfig::from_bytes(path, &contents)?;
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(&(contents.len() as u64).to_be_bytes());
        digest.update(&contents);
        for file in [config.certificate.as_path(), config.private_key.as_path()] {
            let data = read_limited(file, 65_536)?;
            digest.update(&(data.len() as u64).to_be_bytes());
            digest.update(&data);
        }
        if let Some(file) = &config.cover_page {
            digest.update(&read_limited(file, 65_536)?);
        }
        let hash: [u8; 32] = digest.finish().as_ref().try_into().unwrap();
        let server = Server::new(&config)?;
        Ok((hash, config, server))
    }
    let (mut hash, config, mut server) = snapshot(path)?;
    let address = config.listen;
    // Tokio configures SO_REUSEADDR on Unix, so a process restart can rebind
    // while sockets from the previous process are still in TIME_WAIT.
    let listener = TcpListener::bind(address).await?.into_std()?;
    eprintln!(
        "HTTPS server listening on {} (configuration watch enabled)",
        listener.local_addr()?
    );
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let stop = shutdown.child_token();
        let socket = TcpListener::from_std(listener.try_clone()?)?;
        let mut running = tokio::spawn(server.clone().serve(socket, stop.clone()));
        let replacement = loop {
            tokio::select! {
                _ = shutdown.cancelled() => { stop.cancel(); return running.await?; }
                result = &mut running => { return result?; }
                _ = tick.tick() => {
                    match snapshot(path) {
                        Ok((next_hash, next_config, next)) if next_hash != hash && next_config.listen == address => {
                            break (next_hash, next);
                        }
                        Ok(_) => {}
                        Err(_) => { eprintln!("configuration reload rejected; retaining last valid configuration"); }
                    }
                }
            }
        };
        stop.cancel();
        running.await??;
        (hash, server) = replacement;
        eprintln!("configuration reloaded; previous sessions closed");
    }
}

pub struct Server {
    acceptor: TlsAcceptor,
    origin: Origin,
    keys: PublicKeys,
    target: SocketAddr,
    path: String,
    cover: Bytes,
    idle: Duration,
    connections: Arc<Semaphore>,
    tunnels: Arc<Semaphore>,
}

impl Server {
    pub fn new(config: &ServerConfig) -> Result<Arc<Self>> {
        validate_target(config.wireguard_endpoint)?;
        ensure!(
            (1..=4096).contains(&config.max_connections),
            "max_connections must be 1..4096"
        );
        ensure!(
            (1..=4096).contains(&config.max_tunnels),
            "max_tunnels must be 1..4096"
        );
        let cover = match &config.cover_page {
            Some(path) => Bytes::from(read_limited(path, 65_536)?),
            None => Bytes::from_static(DEFAULT_PAGE),
        };
        Ok(Arc::new(Self {
            acceptor: TlsAcceptor::from(crate::tls::server(
                &config.certificate,
                &config.private_key,
            )?),
            origin: Origin::parse(&config.origin)?,
            keys: PublicKeys::new(&config.clients)?,
            target: config.wireguard_endpoint,
            path: target_path(config.wireguard_endpoint),
            cover,
            idle: idle_duration(config.idle_seconds)?,
            connections: Arc::new(Semaphore::new(config.max_connections)),
            tunnels: Arc::new(Semaphore::new(config.max_tunnels)),
        }))
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let (socket, _) = accepted?;
                    let Ok(permit) = self.connections.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        // Do not log requests, credentials, payloads or peer addresses.
                        if let Err(error) = server.connection(socket).await {
                            eprintln!("connection closed: {error}");
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn connection(self: Arc<Self>, socket: TcpStream) -> Result<()> {
        socket.set_nodelay(true)?;
        let tls = timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(socket))
            .await
            .context("TLS handshake timed out")??;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            let server = self.clone();
            let service =
                hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                    let response = server.cover_response(request.method(), request.uri().path());
                    async move { Ok::<_, Infallible>(response.map(Full::new)) }
                });
            // HTTP/1.1 is the ordinary cover site, never an unauthenticated UDP upgrade.
            timeout(
                Duration::from_secs(30),
                hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HANDSHAKE_TIMEOUT)
                    .max_buf_size(16_384)
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(tls), service),
            )
            .await
            .context("HTTP/1.1 request timed out")??;
            return Ok(());
        }
        let verifier = Arc::new(self.keys.bind(&self.origin, |context| {
            Ok(tls
                .get_ref()
                .1
                .export_keying_material([0; 48], LABEL, Some(context))?)
        })?);
        let mut builder = h2::server::Builder::new();
        builder
            .enable_connect_protocol()
            .max_concurrent_streams(8)
            .max_header_list_size(16_384)
            .max_frame_size(16_384)
            .max_send_buffer_size(65_536)
            .initial_window_size(65_535)
            .initial_connection_window_size(1_048_576);
        let mut connection = timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls))
            .await
            .context("HTTP/2 handshake timed out")??;
        let mut requests = JoinSet::new();
        let mut last_request = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            while let Some(result) = requests.try_join_next() {
                if let Ok(Err(error)) = result {
                    eprintln!("request closed: {error}");
                }
            }
            tokio::select! {
                request = connection.accept() => {
                    let Some(request) = request else { break; };
                    let (request, respond) = request?;
                    last_request = Instant::now();
                    let server = self.clone();
                    let verifier = verifier.clone();
                    requests.spawn(async move { server.request(request, respond, &verifier).await });
                }
                result = requests.join_next(), if !requests.is_empty() => {
                    if let Some(Ok(Err(error))) = result { eprintln!("request closed: {error}"); }
                }
                _ = tick.tick() => {
                    if requests.is_empty() && last_request.elapsed() > Duration::from_secs(30) { break; }
                }
            }
        }
        requests.abort_all();
        while requests.join_next().await.is_some() {}
        Ok(())
    }

    async fn request(
        &self,
        request: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        verifier: &Verifier,
    ) -> Result<()> {
        let authorized = request.headers().get_all("authorization").iter().count() == 1
            && verifier.accepts(request.headers().get("authorization"));
        let is_tunnel = authorized
            && self.origin.accepts(request.uri())
            && request.method() == Method::CONNECT
            && request.uri().path() == self.path
            && request.uri().query().is_none()
            && request
                .extensions()
                .get::<h2::ext::Protocol>()
                .is_some_and(|p| p.as_str() == "connect-udp")
            && request.headers().get_all("capsule-protocol").iter().count() == 1
            && request
                .headers()
                .get("capsule-protocol")
                .is_some_and(|h| h == "?1");
        if !is_tunnel {
            let response = self.cover_response(request.method(), request.uri().path());
            let (parts, body) = response.into_parts();
            let mut send =
                respond.send_response(Response::from_parts(parts, ()), body.is_empty())?;
            if !body.is_empty() {
                timeout(WRITE_TIMEOUT, crate::capsule::send_bytes(&mut send, body)).await??;
                send.send_data(Bytes::new(), true)?;
            }
            return Ok(());
        }
        let Ok(_permit) = self.tunnels.clone().try_acquire_owned() else {
            respond.send_response(Response::builder().status(503).body(())?, true)?;
            return Ok(());
        };
        let socket = UdpSocket::bind(if self.target.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .await?;
        socket.connect(self.target).await?;
        let response = Response::builder()
            .status(200)
            .header("capsule-protocol", "?1")
            .body(())?;
        let send = DatagramSender(respond.send_response(response, false)?);
        relay(
            socket,
            DatagramReceiver::new(request.into_body()),
            send,
            self.idle,
        )
        .await
    }

    fn cover_response(&self, method: &Method, path: &str) -> Response<Bytes> {
        let found = (method == Method::GET || method == Method::HEAD) && path == "/";
        let body = if found {
            self.cover.clone()
        } else {
            Bytes::from_static(NOT_FOUND)
        };
        Response::builder()
            .status(if found {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            })
            .header("content-type", "text/html; charset=utf-8")
            .header("content-length", body.len())
            .body(if method == Method::HEAD {
                Bytes::new()
            } else {
                body
            })
            .unwrap()
    }
}

async fn relay(
    socket: UdpSocket,
    mut recv: DatagramReceiver,
    mut send: DatagramSender,
    idle: Duration,
) -> Result<()> {
    let (activity, watch) = watch::channel(Instant::now());
    let upload = async {
        while let Some(packet) = recv.recv().await? {
            activity.send_replace(Instant::now());
            // IPv4 has eight fewer usable bytes than the RFC's IPv6 maximum.
            if socket.peer_addr()?.is_ipv4() && packet.len() > 65_507 {
                continue;
            }
            match timeout(WRITE_TIMEOUT, socket.send(&packet)).await? {
                Ok(_) => {}
                // RFC 9298: a datagram exceeding the actual UDP/MTU limit is dropped.
                Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        let mut buffer = vec![0; MAX_UDP + 1];
        loop {
            let size = socket.recv(&mut buffer).await?;
            if size > MAX_UDP {
                continue;
            }
            activity.send_replace(Instant::now());
            timeout(WRITE_TIMEOUT, send.send(&buffer[..size])).await??;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        _ = crate::idle_timeout(watch, idle) => Ok(()),
    }
}
