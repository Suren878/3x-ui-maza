use anyhow::Result;
use clap::Parser;
use maza::{client::Client, config::ClientConfig};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "Local UDP-to-HTTPS transport for a WireGuard client")]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = ClientConfig::load(&args.config)?;
    let client = Arc::new(Client::new(&config)?);
    if args.check {
        println!("Client configuration is valid");
        return Ok(());
    }
    let socket = tokio::net::UdpSocket::bind(config.listen).await?;
    eprintln!("Local UDP listener on {}", socket.local_addr()?);
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        maza::shutdown_signal().await;
        stop.cancel();
    });
    client.serve(socket, shutdown).await
}
