use crate::config::read_limited;
use anyhow::{Context, Result, ensure};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::{io::BufReader, path::Path, sync::Arc};

pub fn client(ca: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        let bytes = read_limited(path, 1_048_576)?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "CA file contains no certificates");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

pub fn server(certificate: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let cert_bytes = read_limited(certificate, 1_048_576)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key_bytes = read_limited(key, 65_536)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))?
        .context("TLS key file is empty")?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
