use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use maza::auth::{Identity, generate_key};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Generate a separate Ed25519 key for Concealed authentication"
)]
struct Args {
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "desktop")]
    id: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bytes = generate_key()?;
    let identity = Identity::from_pkcs8(args.id, &bytes)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&args.out)
        .context("cannot create key file (existing keys are never overwritten)")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!(
        "public_key = \"{}\"",
        URL_SAFE_NO_PAD.encode(identity.public_key())
    );
    eprintln!("Private key saved to {}", args.out.display());
    Ok(())
}
