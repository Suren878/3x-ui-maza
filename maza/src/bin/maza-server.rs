use anyhow::Result;
use clap::Parser;
use maza::{config::ServerConfig, server::Server};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "Experimental authenticated HTTPS-to-WireGuard relay")]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
    /// Reload validated configuration/certificates and close old sessions on change.
    #[arg(long)]
    watch: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = ServerConfig::load(&args.config)?;
    let server = Server::new(&config)?;
    if args.check {
        println!("Server configuration is valid");
        return Ok(());
    }
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        maza::shutdown_signal().await;
        stop.cancel();
    });
    if args.watch {
        maza::server::serve_reloading(&args.config, shutdown).await
    } else {
        let listener = tokio::net::TcpListener::bind(config.listen).await?;
        eprintln!("HTTPS server listening on {}", listener.local_addr()?);
        server.serve(listener, shutdown).await
    }
}
