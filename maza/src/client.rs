use crate::{
    auth::{Identity, LABEL},
    capsule::{DatagramReceiver, DatagramSender, MAX_UDP},
    config::{ClientConfig, Origin, idle_duration, validate_target},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{Method, Request};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct Client {
    origin: Origin,
    address: Option<SocketAddr>,
    target: SocketAddr,
    identity: Identity,
    connector: TlsConnector,
    idle: Duration,
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Tunnel {
    sender: DatagramSender,
    receiver: DatagramReceiver,
    _driver: Driver,
}

impl Tunnel {
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.sender.send(payload).await
    }

    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        self.receiver.recv().await
    }

    /// Borrow both directions while retaining the connection task in this owner.
    /// Returning owned streams would let Rust's disjoint async capture drop the driver early.
    pub fn split(&mut self) -> (&mut DatagramSender, &mut DatagramReceiver) {
        (&mut self.sender, &mut self.receiver)
    }
}

impl Client {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        validate_target(config.wireguard_endpoint)?;
        ensure!(
            config.listen.ip().is_loopback(),
            "local UDP listener must use a loopback address"
        );
        Ok(Self {
            origin: Origin::parse(&config.origin)?,
            address: config.server_address,
            target: config.wireguard_endpoint,
            identity: Identity::load(config.key_id.clone(), &config.private_key)?,
            connector: TlsConnector::from(crate::tls::client(config.ca_certificate.as_deref())?),
            idle: idle_duration(config.idle_seconds)?,
        })
    }

    pub async fn connect(&self) -> Result<Tunnel> {
        timeout(CONNECT_TIMEOUT, self.connect_inner())
            .await
            .context("HTTPS tunnel connection timed out")?
    }

    async fn connect_inner(&self) -> Result<Tunnel> {
        let socket = match self.address {
            Some(address) => TcpStream::connect(address).await?,
            None => TcpStream::connect((self.origin.host.as_str(), self.origin.port)).await?,
        };
        socket.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(self.origin.host.clone())?;
        let tls = self
            .connector
            .connect(name, socket)
            .await
            .context("TLS certificate or handshake rejected")?;
        ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "server did not negotiate HTTP/2"
        );
        let authorization = self.identity.authorization(&self.origin, |context| {
            Ok(tls
                .get_ref()
                .1
                .export_keying_material([0; 48], LABEL, Some(context))?)
        })?;
        let (sender, connection) = h2::client::Builder::new()
            .max_header_list_size(16_384)
            .max_frame_size(16_384)
            .max_send_buffer_size(65_536)
            .initial_window_size(65_535)
            .initial_connection_window_size(1_048_576)
            .handshake(tls)
            .await?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut sender = sender.ready().await?;
        // A normal request both exercises the cover site and waits for the peer's SETTINGS.
        let request = Request::builder()
            .method(Method::GET)
            .uri(self.origin.uri.clone())
            .body(())?;
        let (response, _) = sender.send_request(request, true)?;
        let mut body = response.await?.into_body();
        let mut received = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            received += chunk.len();
            ensure!(received <= 65_536, "cover response exceeds size limit");
            body.flow_control().release_capacity(chunk.len())?;
        }
        ensure!(
            sender.is_extended_connect_protocol_enabled(),
            "server does not support Extended CONNECT"
        );
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(self.origin.request_uri(self.target)?)
            .header("capsule-protocol", "?1")
            .header("authorization", authorization)
            .body(())?;
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static("connect-udp"));
        let mut sender = sender.ready().await?;
        let (response, send) = sender.send_request(request, false)?;
        let response = response.await?;
        ensure!(
            response.status().is_success(),
            "tunnel request rejected (HTTP {})",
            response.status().as_u16()
        );
        ensure!(
            response
                .headers()
                .get_all("capsule-protocol")
                .iter()
                .count()
                == 1
                && response
                    .headers()
                    .get("capsule-protocol")
                    .is_some_and(|h| h == "?1"),
            "server did not confirm capsules"
        );
        Ok(Tunnel {
            sender: DatagramSender(send),
            receiver: DatagramReceiver::new(response.into_body()),
            _driver: driver,
        })
    }

    /// A separate authenticated tunnel per local UDP source prevents cross-peer replies.
    pub async fn serve(
        self: Arc<Self>,
        socket: UdpSocket,
        shutdown: CancellationToken,
    ) -> Result<()> {
        ensure!(
            socket.local_addr()?.ip().is_loopback(),
            "UDP listener must be local"
        );
        let socket = Arc::new(socket);
        let mut peers: HashMap<SocketAddr, (u64, mpsc::Sender<Bytes>)> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut generation = 0u64;
        let mut buffer = vec![0; MAX_UDP + 1];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok((peer, id))) = completed
                        && peers.get(&peer).is_some_and(|entry| entry.0 == id) {
                        peers.remove(&peer);
                    }
                }
                packet = socket.recv_from(&mut buffer) => {
                    let (size, peer) = packet?;
                    if size > MAX_UDP || !peer.ip().is_loopback() { continue; }
                    if peers.get(&peer).is_some_and(|entry| entry.1.is_closed()) { peers.remove(&peer); }
                    if !peers.contains_key(&peer) {
                        if peers.len() >= 16 { continue; }
                        let (send, recv) = mpsc::channel(16);
                        generation += 1;
                        let id = generation;
                        peers.insert(peer, (id, send));
                        let client = self.clone();
                        let socket = socket.clone();
                        tasks.spawn(async move {
                            client.peer(socket, peer, recv).await;
                            (peer, id)
                        });
                    }
                    // UDP overload drops packets instead of growing a queue without bound.
                    let _ = peers[&peer].1.try_send(Bytes::copy_from_slice(&buffer[..size]));
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn peer(
        &self,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        mut packets: mpsc::Receiver<Bytes>,
    ) {
        let mut delay = 1;
        loop {
            let first = match timeout(self.idle, packets.recv()).await {
                Ok(Some(p)) => p,
                _ => return,
            };
            let mut tunnel = match self.connect().await {
                Ok(tunnel) => {
                    delay = 1;
                    tunnel
                }
                Err(error) => {
                    eprintln!("HTTPS connection failed: {error}; retrying on local traffic");
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    delay = (delay * 2).min(15);
                    continue;
                }
            };
            eprintln!("HTTPS tunnel connected");
            let (activity, watch) = watch::channel(Instant::now());
            let upload = async {
                timeout(WRITE_TIMEOUT, tunnel.sender.send(&first)).await??;
                while let Some(packet) = packets.recv().await {
                    activity.send_replace(Instant::now());
                    timeout(WRITE_TIMEOUT, tunnel.sender.send(&packet)).await??;
                }
                Ok::<_, anyhow::Error>(())
            };
            let download = async {
                while let Some(packet) = tunnel.receiver.recv().await? {
                    activity.send_replace(Instant::now());
                    match timeout(WRITE_TIMEOUT, socket.send_to(&packet, peer)).await? {
                        Ok(_) => {}
                        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::select! {
                result = upload => { if let Err(error) = result { eprintln!("tunnel upload ended: {error}"); } }
                result = download => { if let Err(error) = result { eprintln!("tunnel download ended: {error}"); } }
                _ = crate::idle_timeout(watch, self.idle) => return,
            }
            // Close the old connection before attempting a new one. Never fall back to plain UDP.
            drop(tunnel);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
