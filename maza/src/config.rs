use anyhow::{Context, Result, ensure};
use http::Uri;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Origin {
    pub uri: Uri,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn parse(value: &str) -> Result<Self> {
        let uri: Uri = value.parse().context("invalid origin URL")?;
        ensure!(uri.scheme_str() == Some("https"), "origin must use https");
        let authority = uri.authority().context("origin needs a hostname")?;
        ensure!(
            !authority.as_str().contains('@'),
            "origin must not contain user information"
        );
        ensure!(
            uri.path() == "/" || uri.path().is_empty(),
            "origin must not contain a path"
        );
        ensure!(uri.query().is_none(), "origin must not contain a query");
        let host = uri
            .host()
            .context("origin needs a hostname")?
            .to_ascii_lowercase();
        let port = uri.port_u16().unwrap_or(443);
        ensure!(port != 0, "origin port must be nonzero");
        Ok(Self { uri, host, port })
    }

    pub fn accepts(&self, uri: &Uri) -> bool {
        uri.scheme_str() == Some("https")
            && uri
                .host()
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && uri.port_u16().unwrap_or(443) == self.port
            && !uri.authority().is_some_and(|a| a.as_str().contains('@'))
    }

    pub fn request_uri(&self, target: SocketAddr) -> Result<Uri> {
        Ok(Uri::builder()
            .scheme("https")
            .authority(self.uri.authority().unwrap().as_str())
            .path_and_query(target_path(target))
            .build()?)
    }
}

pub fn target_path(target: SocketAddr) -> String {
    let host = target.ip().to_string().replace(':', "%3A");
    format!("/.well-known/masque/udp/{host}/{}/", target.port())
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedKey {
    pub id: String,
    pub public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub origin: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub wireguard_endpoint: SocketAddr,
    pub clients: Vec<AuthorizedKey>,
    pub cover_page: Option<PathBuf>,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    #[serde(default = "default_tunnels")]
    pub max_tunnels: usize,
    #[serde(default = "default_idle")]
    pub idle_seconds: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub origin: String,
    /// Optional direct address; TLS still verifies the hostname from origin.
    pub server_address: Option<SocketAddr>,
    pub listen: SocketAddr,
    pub wireguard_endpoint: SocketAddr,
    pub key_id: String,
    pub private_key: PathBuf,
    pub ca_certificate: Option<PathBuf>,
    #[serde(default = "default_idle")]
    pub idle_seconds: u64,
}

fn default_connections() -> usize {
    128
}
fn default_tunnels() -> usize {
    64
}
fn default_idle() -> u64 {
    180
}

pub fn read_config<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let content = read_limited(path, 65_536)?;
    toml::from_str(std::str::from_utf8(&content)?).context("invalid configuration")
}

pub fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= limit,
        "file exceeds size limit: {}",
        path.display()
    );
    Ok(data)
}

fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

pub fn validate_target(target: SocketAddr) -> Result<()> {
    ensure!(
        target.ip().is_loopback() && target.port() != 0,
        "WireGuard endpoint must be a loopback address with a nonzero port"
    );
    Ok(())
}

pub fn idle_duration(seconds: u64) -> Result<Duration> {
    ensure!(
        (10..=3600).contains(&seconds),
        "idle_seconds must be between 10 and 3600"
    );
    Ok(Duration::from_secs(seconds))
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_bytes(path, &read_limited(path, 65_536)?)
    }

    pub(crate) fn from_bytes(path: &Path, content: &[u8]) -> Result<Self> {
        let mut config: Self =
            toml::from_str(std::str::from_utf8(content)?).context("invalid configuration")?;
        let base = path.parent().unwrap_or(Path::new("."));
        resolve(base, &mut config.certificate);
        resolve(base, &mut config.private_key);
        if let Some(cover) = &mut config.cover_page {
            resolve(base, cover);
        }
        Ok(config)
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = read_config(path)?;
        let base = path.parent().unwrap_or(Path::new("."));
        resolve(base, &mut config.private_key);
        if let Some(ca) = &mut config.ca_certificate {
            resolve(base, ca);
        }
        Ok(config)
    }
}
