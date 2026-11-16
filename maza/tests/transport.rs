use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use maza::{
    auth::{Identity, LABEL, generate_key},
    client::Client,
    config::{AuthorizedKey, ClientConfig, Origin, ServerConfig, target_path},
    server::Server,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const DEADLINE: Duration = Duration::from_secs(10);

struct Fixture {
    _directory: TempDir,
    config: ClientConfig,
    server_config: ServerConfig,
    identity: Identity,
    stop: CancellationToken,
    task: JoinHandle<Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Fixture {
    async fn start(target: SocketAddr) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.path().join("certificate.pem");
        let tls_key = directory.path().join("tls-key.pem");
        let client_key = directory.path().join("client.pk8");
        std::fs::write(&cert_path, certificate.cert.pem()).unwrap();
        std::fs::write(&tls_key, certificate.key_pair.serialize_pem()).unwrap();
        let key = generate_key().unwrap();
        std::fs::write(&client_key, &key).unwrap();
        let identity = Identity::from_pkcs8("desktop".into(), &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("https://localhost:{}", address.port());
        let server_config = ServerConfig {
            listen: address,
            origin: origin.clone(),
            certificate: cert_path.clone(),
            private_key: tls_key,
            wireguard_endpoint: target,
            clients: vec![AuthorizedKey {
                id: identity.id.clone(),
                public_key: B64.encode(identity.public_key()),
            }],
            cover_page: None,
            max_connections: 32,
            max_tunnels: 16,
            idle_seconds: 10,
        };
        let config = ClientConfig {
            origin,
            server_address: Some(address),
            listen: "127.0.0.1:0".parse().unwrap(),
            wireguard_endpoint: target,
            key_id: identity.id.clone(),
            private_key: client_key,
            ca_certificate: Some(cert_path),
            idle_seconds: 10,
        };
        let stop = CancellationToken::new();
        let server = Server::new(&server_config).unwrap();
        let task = tokio::spawn(server.serve(listener, stop.clone()));
        Self {
            _directory: directory,
            config,
            server_config,
            identity,
            stop,
            task,
        }
    }
}

async fn echo() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65_536];
        loop {
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..size], peer).await.unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn watched_config_revokes_existing_sessions_and_rejects_invalid_updates() {
    let (target, echo) = echo().await;
    let mut fixture = Fixture::start(target).await;
    fixture.stop.cancel();
    timeout(DEADLINE, &mut fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let path = fixture._directory.path().join("watched.toml");
    let prefix = format!(
        "listen = {:?}\norigin = {:?}\ncertificate = \"certificate.pem\"\nprivate_key = \"tls-key.pem\"\nwireguard_endpoint = {:?}\n",
        fixture.server_config.listen.to_string(),
        fixture.config.origin,
        target.to_string()
    );
    let allowed = format!(
        "{prefix}[[clients]]\nid = \"desktop\"\npublic_key = {:?}\n",
        B64.encode(fixture.identity.public_key())
    );
    std::fs::write(&path, &allowed).unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let watched = path.clone();
    let mut running =
        tokio::spawn(async move { maza::server::serve_reloading(&watched, shutdown).await });
    let client = Client::new(&fixture.config).unwrap();
    let mut tunnel = timeout(DEADLINE, async {
        loop {
            if let Ok(t) = client.connect().await {
                break t;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    tunnel.send(b"before").await.unwrap();
    assert_eq!(tunnel.recv().await.unwrap().unwrap(), b"before"[..]);
    std::fs::write(&path, "invalid TOML !!!").unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    tunnel.send(b"retained").await.unwrap();
    assert_eq!(
        timeout(DEADLINE, tunnel.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"retained"[..]
    );
    std::fs::write(&path, format!("{prefix}clients = []\n")).unwrap();
    let closed = timeout(Duration::from_secs(4), tunnel.recv())
        .await
        .unwrap();
    assert!(
        !matches!(closed, Ok(Some(_))),
        "revoked session stayed open"
    );
    assert!(
        timeout(DEADLINE, client.connect()).await.unwrap().is_err(),
        "revoked key reconnected"
    );
    stop.cancel();
    timeout(DEADLINE, &mut running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    echo.abort();
}

#[tokio::test]
async fn datagrams_cross_real_tls_h2_and_udp_with_flow_control() {
    let (target, echo) = echo().await;
    let fixture = Fixture::start(target).await;
    let client = Client::new(&fixture.config).unwrap();
    let mut a = client.connect().await.unwrap();
    let mut b = client.connect().await.unwrap();
    let transfer = |mut tunnel: maza::client::Tunnel, marker| async move {
        for size in [0, 1, 148, 92, 1420, 4096, 8192]
            .into_iter()
            .cycle()
            .take(140)
        {
            let bytes = vec![marker; size];
            timeout(DEADLINE, tunnel.send(&bytes))
                .await
                .unwrap()
                .unwrap();
            let reply = timeout(DEADLINE, tunnel.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(reply.as_ref(), bytes);
        }
    };
    a.send(b"a").await.unwrap();
    b.send(b"b").await.unwrap();
    assert_eq!(a.recv().await.unwrap().unwrap(), b"a"[..]);
    assert_eq!(b.recv().await.unwrap().unwrap(), b"b"[..]);
    tokio::join!(transfer(a, 23), transfer(b, 71));
    echo.abort();
}

#[tokio::test]
async fn untrusted_certificate_wrong_hostname_and_wrong_client_key_fail_closed() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::start(target.local_addr().unwrap()).await;
    let mut config = fixture.config.clone();
    config.ca_certificate = None;
    assert!(Client::new(&config).unwrap().connect().await.is_err());
    config = fixture.config.clone();
    config.origin = config.origin.replace("localhost", "wrong.example");
    assert!(Client::new(&config).unwrap().connect().await.is_err());
    config = fixture.config.clone();
    let wrong = fixture._directory.path().join("wrong.pk8");
    std::fs::write(&wrong, generate_key().unwrap()).unwrap();
    config.private_key = wrong;
    assert!(Client::new(&config).unwrap().connect().await.is_err());
    let mut bytes = [0; 2048];
    assert!(
        timeout(Duration::from_millis(100), target.recv(&mut bytes))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn oversized_udp_is_dropped_without_closing_the_tunnel() {
    let (target, echo) = echo().await;
    let fixture = Fixture::start(target).await;
    let mut tunnel = Client::new(&fixture.config)
        .unwrap()
        .connect()
        .await
        .unwrap();
    // Legal for RFC 9298/IPv6, but too large for this server's IPv4 endpoint.
    tunnel
        .send(&vec![42; maza::capsule::MAX_UDP])
        .await
        .unwrap();
    // macOS also has a lower socket UDP limit: exercise the EMSGSIZE path.
    #[cfg(target_os = "macos")]
    tunnel.send(&vec![42; 60_000]).await.unwrap();
    tunnel.send(b"still-open").await.unwrap();
    assert_eq!(
        timeout(DEADLINE, tunnel.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"still-open"[..]
    );
    echo.abort();
}

struct Raw {
    sender: h2::client::SendRequest<Bytes>,
    proof: http::HeaderValue,
    origin: Origin,
    task: JoinHandle<()>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Raw {
    async fn new(fixture: &Fixture) -> Self {
        let origin = Origin::parse(&fixture.config.origin).unwrap();
        let socket = TcpStream::connect(fixture.config.server_address.unwrap())
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(
            maza::tls::client(fixture.config.ca_certificate.as_deref()).unwrap(),
        )
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await
        .unwrap();
        let proof = fixture
            .identity
            .authorization(&origin, |context| {
                Ok(tls
                    .get_ref()
                    .1
                    .export_keying_material([0; 48], LABEL, Some(context))?)
            })
            .unwrap();
        let (sender, connection) = h2::client::handshake(tls).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut raw = Self {
            sender,
            proof,
            origin,
            task,
        };
        let response = raw.request(Method::GET, "/", None).await;
        assert_eq!(response.0, StatusCode::OK);
        raw
    }

    async fn request(
        &mut self,
        method: Method,
        path: &str,
        proof: Option<http::HeaderValue>,
    ) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(self.origin.uri.authority().unwrap().as_str())
            .path_and_query(path)
            .build()
            .unwrap();
        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri)
            .body(())
            .unwrap();
        if method == Method::CONNECT {
            request
                .extensions_mut()
                .insert(h2::ext::Protocol::from_static("connect-udp"));
            request
                .headers_mut()
                .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
        }
        if let Some(proof) = proof {
            request.headers_mut().insert("authorization", proof);
        }
        let (response, _send) = self
            .sender
            .send_request(request, method != Method::CONNECT)
            .unwrap();
        let response = timeout(DEADLINE, response).await.unwrap().unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let mut stream = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = timeout(DEADLINE, stream.data()).await.unwrap() {
            let chunk = chunk.unwrap();
            body.extend_from_slice(&chunk);
            stream.flow_control().release_capacity(chunk.len()).unwrap();
        }
        (status, headers, body)
    }
}

#[tokio::test]
async fn tls_bound_auth_replay_and_probes_return_the_same_404_as_unknown_resources() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::start(target.local_addr().unwrap()).await;
    let original = Raw::new(&fixture).await;
    let replay = original.proof.clone();
    drop(original);
    let mut raw = Raw::new(&fixture).await;
    assert_ne!(replay, raw.proof);
    let path = target_path(target.local_addr().unwrap());
    let missing = raw.request(Method::CONNECT, "/missing", None).await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert!(!missing.1.contains_key("www-authenticate"));
    assert!(!missing.1.contains_key("capsule-protocol"));
    assert_eq!(raw.request(Method::CONNECT, &path, None).await, missing);
    assert_eq!(
        raw.request(Method::CONNECT, &path, Some(replay)).await,
        missing
    );
    assert_eq!(
        raw.request(
            Method::CONNECT,
            &path,
            Some(http::HeaderValue::from_static("Concealed nonsense"))
        )
        .await,
        missing
    );
    let proof = raw.proof.clone();
    assert_eq!(
        raw.request(
            Method::CONNECT,
            "/.well-known/masque/udp/127.0.0.1/1/",
            Some(proof)
        )
        .await,
        missing
    );
    let mut bytes = [0; 2048];
    assert!(
        timeout(Duration::from_millis(100), target.recv(&mut bytes))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ordinary_http1_browser_can_read_the_cover_page() {
    let (target, echo) = echo().await;
    let fixture = Fixture::start(target).await;
    let mut config =
        (*maza::tls::client(fixture.config.ca_certificate.as_deref()).unwrap()).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let socket = TcpStream::connect(fixture.config.server_address.unwrap())
        .await
        .unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            socket,
        )
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    timeout(DEADLINE, tls.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(text.contains("Welcome"));
    assert!(!text.to_lowercase().contains("maza"));
    echo.abort();
}

#[tokio::test]
async fn loopback_bridge_isolates_peers_and_recovers_after_server_restart() {
    let (target, echo) = echo().await;
    let mut fixture = Fixture::start(target).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let stop = CancellationToken::new();
    let client = Arc::new(Client::new(&fixture.config).unwrap());
    let bridge = tokio::spawn(client.serve(socket, stop.clone()));
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(address).await.unwrap();
    b.connect(address).await.unwrap();
    let mut bytes = [0; 1024];
    a.send(b"client-a").await.unwrap();
    b.send(b"client-b").await.unwrap();
    let size = timeout(DEADLINE, a.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..size], b"client-a");
    let size = timeout(DEADLINE, b.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..size], b"client-b");
    fixture.stop.cancel();
    timeout(DEADLINE, &mut fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Parallel CLI tests can briefly retain an inherited descriptor between
    // fork and exec. Allow the same bounded rebind grace as a service restart.
    let listener = timeout(Duration::from_secs(2), async {
        loop {
            match TcpListener::bind(fixture.server_config.listen).await {
                Ok(listener) => break listener,
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("could not rebind test listener: {e}"),
            }
        }
    })
    .await
    .unwrap();
    fixture.stop = CancellationToken::new();
    fixture.task = tokio::spawn(
        Server::new(&fixture.server_config)
            .unwrap()
            .serve(listener, fixture.stop.clone()),
    );
    let mut recovered = false;
    for _ in 0..12 {
        a.send(b"after-restart").await.unwrap();
        if let Ok(Ok(size)) = timeout(Duration::from_millis(500), a.recv(&mut bytes)).await {
            assert_eq!(&bytes[..size], b"after-restart");
            recovered = true;
            break;
        }
    }
    assert!(recovered, "bridge did not reconnect");
    stop.cancel();
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
    echo.abort();
}

#[test]
fn keygen_does_not_overwrite_keys_and_keeps_them_private() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.pk8");
    let first = std::process::Command::new(env!("CARGO_BIN_EXE_maza-keygen"))
        .arg("--out")
        .arg(&path)
        .output()
        .unwrap();
    assert!(first.status.success());
    let original = std::fs::read(&path).unwrap();
    Identity::from_pkcs8("desktop".into(), &original).unwrap();
    let second = std::process::Command::new(env!("CARGO_BIN_EXE_maza-keygen"))
        .arg("--out")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn packaged_cli_programs_read_relative_paths_and_relay_udp() {
    use std::process::{Command, Stdio};
    let (target, echo) = echo().await;
    let mut fixture = Fixture::start(target).await;
    fixture.stop.cancel();
    timeout(DEADLINE, &mut fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_address = local.local_addr().unwrap();
    drop(local);
    let server_path = fixture._directory.path().join("server.toml");
    let client_path = fixture._directory.path().join("client.toml");
    std::fs::write(&server_path, format!(
        "listen = {:?}\norigin = {:?}\ncertificate = \"certificate.pem\"\nprivate_key = \"tls-key.pem\"\nwireguard_endpoint = {:?}\n[[clients]]\nid = \"desktop\"\npublic_key = {:?}\n",
        fixture.server_config.listen.to_string(), fixture.config.origin, target.to_string(), B64.encode(fixture.identity.public_key())
    )).unwrap();
    std::fs::write(&client_path, format!(
        "listen = {:?}\norigin = {:?}\nserver_address = {:?}\nwireguard_endpoint = {:?}\nkey_id = \"desktop\"\nprivate_key = \"client.pk8\"\nca_certificate = \"certificate.pem\"\n",
        local_address.to_string(), fixture.config.origin, fixture.server_config.listen.to_string(), target.to_string()
    )).unwrap();
    for (binary, config) in [
        (env!("CARGO_BIN_EXE_maza-server"), &server_path),
        (env!("CARGO_BIN_EXE_maza-client"), &client_path),
    ] {
        let result = Command::new(binary)
            .arg("--config")
            .arg(config)
            .arg("--check")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let mut server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_maza-server"))
            .arg("--config")
            .arg(&server_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut client = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_maza-client"))
            .arg("--config")
            .arg(&client_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = vec![19; 4096];
    let mut buffer = vec![0; 8192];
    let mut received = false;
    for _ in 0..50 {
        assert!(server.0.try_wait().unwrap().is_none(), "server exited");
        assert!(client.0.try_wait().unwrap().is_none(), "client exited");
        socket.send_to(&packet, local_address).await.unwrap();
        if let Ok(Ok((size, source))) =
            timeout(Duration::from_millis(100), socket.recv_from(&mut buffer)).await
        {
            assert_eq!(source, local_address);
            assert_eq!(&buffer[..size], &packet);
            received = true;
            break;
        }
    }
    assert!(received, "CLI programs did not relay traffic");
    echo.abort();
}

fn ip_packet(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&5300u16.to_be_bytes());
    packet[22..24].copy_from_slice(&5300u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    let sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u32::from(u16::from_be_bytes([v[0], v[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn wg_exchange(
    peer: &mut awgtun::noise::Tunn,
    transport: &UdpSocket,
    payload: &[u8],
) -> Vec<u8> {
    use awgtun::noise::TunnResult;
    let packet = ip_packet([10, 77, 0, 2], [10, 77, 0, 1], payload);
    let mut output = vec![0; 65_536];
    match peer.encapsulate(&packet, &mut output) {
        TunnResult::WriteToNetwork(bytes) => {
            transport.send(bytes).await.unwrap();
        }
        _ => panic!("WireGuard produced no initiation or data"),
    }
    let mut input = vec![0; 65_536];
    loop {
        let size = timeout(DEADLINE, transport.recv(&mut input))
            .await
            .unwrap()
            .unwrap();
        let mut next = &input[..size];
        loop {
            match peer.decapsulate(None, next, &mut output) {
                TunnResult::WriteToNetwork(bytes) => {
                    transport.send(bytes).await.unwrap();
                }
                TunnResult::WriteToTunnelV4(bytes, _) => {
                    assert_eq!(&bytes[12..16], &[10, 77, 0, 1]);
                    assert_eq!(&bytes[16..20], &[10, 77, 0, 2]);
                    return bytes[28..].to_vec();
                }
                TunnResult::Done => break,
                _ => panic!("WireGuard rejected peer data"),
            }
            // Drain packets buffered until the handshake completed.
            next = &[];
        }
    }
}

#[tokio::test]
async fn wireguard_upload_and_download_a_megabyte_file_through_the_https_bridge() {
    use awgtun::{
        noise::{Tunn, TunnResult},
        x25519::{PublicKey, StaticSecret},
    };
    use ring::digest::{SHA256, digest};
    const CHUNK: usize = 4096;
    const SIZE: usize = 1_048_576;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::start(target.local_addr().unwrap()).await;
    let source_path = fixture._directory.path().join("original.bin");
    let uploaded_path = fixture._directory.path().join("uploaded.bin");
    let downloaded_path = fixture._directory.path().join("downloaded.bin");
    let bytes: Vec<u8> = (0..SIZE)
        .map(|i| ((i * 31) ^ (i >> 8) ^ (i >> 16)) as u8)
        .collect();
    std::fs::write(&source_path, &bytes).unwrap();
    let original = std::fs::read(&source_path).unwrap();
    let expected_hash = digest(&SHA256, &original);
    let server_file = uploaded_path.clone();
    let wg_server = tokio::spawn(async move {
        let mut peer = Tunn::new(
            StaticSecret::from([9; 32]),
            PublicKey::from(&StaticSecret::from([7; 32])),
            Some([11; 32]),
            None,
            1,
            None,
        );
        let mut input = vec![0; 65_536];
        let mut output = vec![0; 65_536];
        let mut file = Vec::new();
        loop {
            let (size, address) = timeout(DEADLINE, target.recv_from(&mut input))
                .await
                .unwrap()
                .unwrap();
            match peer.decapsulate(Some(address.ip()), &input[..size], &mut output) {
                TunnResult::WriteToNetwork(bytes) => {
                    target.send_to(bytes, address).await.unwrap();
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    let request = &packet[28..];
                    let reply = match request[0] {
                        0 => {
                            let offset =
                                u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize;
                            assert_eq!(offset, file.len());
                            file.extend_from_slice(&request[5..]);
                            request[..5].to_vec()
                        }
                        1 => {
                            assert_eq!(file.len(), SIZE);
                            std::fs::write(&server_file, &file).unwrap();
                            file = std::fs::read(&server_file).unwrap();
                            [vec![1], digest(&SHA256, &file).as_ref().to_vec()].concat()
                        }
                        2 => {
                            let offset =
                                u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize;
                            [request[..5].to_vec(), file[offset..offset + CHUNK].to_vec()].concat()
                        }
                        3 => vec![3],
                        _ => panic!("unexpected file-transfer request"),
                    };
                    let finished = request[0] == 3;
                    let packet = ip_packet([10, 77, 0, 1], [10, 77, 0, 2], &reply);
                    match peer.encapsulate(&packet, &mut output) {
                        TunnResult::WriteToNetwork(bytes) => {
                            target.send_to(bytes, address).await.unwrap();
                        }
                        _ => panic!("WireGuard server produced no encrypted response"),
                    }
                    if finished {
                        break;
                    }
                }
                TunnResult::Done => {}
                _ => panic!("WireGuard server rejected input"),
            }
        }
    });
    let bridge_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bridge_address = bridge_socket.local_addr().unwrap();
    let stop = CancellationToken::new();
    let bridge = tokio::spawn(
        Arc::new(Client::new(&fixture.config).unwrap()).serve(bridge_socket, stop.clone()),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(bridge_address).await.unwrap();
    let mut peer = Tunn::new(
        StaticSecret::from([7; 32]),
        PublicKey::from(&StaticSecret::from([9; 32])),
        Some([11; 32]),
        None,
        2,
        None,
    );
    for (index, bytes) in original.chunks(CHUNK).enumerate() {
        let offset = (index * CHUNK) as u32;
        let request = [vec![0], offset.to_be_bytes().to_vec(), bytes.to_vec()].concat();
        assert_eq!(
            wg_exchange(&mut peer, &socket, &request).await,
            request[..5]
        );
    }
    let upload_hash = wg_exchange(&mut peer, &socket, &[1]).await;
    assert_eq!(&upload_hash[1..], expected_hash.as_ref());
    let mut downloaded = Vec::new();
    for offset in (0..SIZE).step_by(CHUNK) {
        let request = [vec![2], (offset as u32).to_be_bytes().to_vec()].concat();
        let response = wg_exchange(&mut peer, &socket, &request).await;
        assert_eq!(&response[..5], &request);
        downloaded.extend_from_slice(&response[5..]);
    }
    std::fs::write(&downloaded_path, &downloaded).unwrap();
    assert_eq!(
        digest(&SHA256, &std::fs::read(&downloaded_path).unwrap()).as_ref(),
        expected_hash.as_ref()
    );
    assert_eq!(std::fs::read(&uploaded_path).unwrap(), original);
    assert_eq!(wg_exchange(&mut peer, &socket, &[3]).await, [3]);
    timeout(DEADLINE, wg_server).await.unwrap().unwrap();
    stop.cancel();
    timeout(DEADLINE, bridge).await.unwrap().unwrap().unwrap();
}
