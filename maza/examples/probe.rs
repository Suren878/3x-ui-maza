//! Verify an exported profile against a real relay and WireGuard backend without
//! a TUN interface, routes, DNS changes, or traffic to any third-party service.
use anyhow::{Context, Result, bail, ensure};
use awgtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use maza::{
    client::Client,
    config::{ClientConfig, read_limited},
};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    wireguard: PathBuf,
}

fn field(text: &str, name: &str) -> Result<[u8; 32]> {
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
        .collect();
    ensure!(values.len() == 1, "expected exactly one {name}");
    STANDARD
        .decode(values[0])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {name} length"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = ClientConfig::load(&args.config)?;
    let data = read_limited(&args.wireguard, 16_384)?;
    let text = std::str::from_utf8(&data)?;
    let mut peer = Tunn::new(
        StaticSecret::from(field(text, "PrivateKey")?),
        PublicKey::from(field(text, "PublicKey")?),
        None,
        None,
        5,
        None,
    );
    let mut tunnel = tokio::time::timeout(Duration::from_secs(15), Client::new(&cfg)?.connect())
        .await
        .context("HTTPS connection timed out")??;
    let mut output = vec![0u8; 65_536];
    match peer.format_handshake_initiation(&mut output, false) {
        TunnResult::WriteToNetwork(bytes) => tunnel.send(bytes).await?,
        _ => bail!("failed to generate WireGuard handshake"),
    }
    let reply = tokio::time::timeout(Duration::from_secs(15), tunnel.recv())
        .await
        .context("WireGuard response timed out")??
        .context("relay closed")?;
    match peer.decapsulate(None, &reply, &mut output) {
        TunnResult::WriteToNetwork(bytes) => tunnel.send(bytes).await?,
        TunnResult::Done => {}
        _ => bail!("WireGuard rejected the server response"),
    }
    ensure!(
        peer.time_since_last_handshake().is_some(),
        "WireGuard handshake did not complete"
    );
    println!("TLS certificate, MAZA authentication and WireGuard handshake verified");
    Ok(())
}
