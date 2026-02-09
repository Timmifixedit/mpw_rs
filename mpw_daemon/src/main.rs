mod request_handler;

use clap::Parser;
use log::{error, info, warn};
use mpw_core::vault::Vault;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "MPW Vault Daemon",
    long_about = "MPW Vault Daemon: Manages a vault and provides an interface via UDS"
)]
struct Args {
    #[arg(required = true)]
    vault_path: PathBuf,
    #[arg(short, long, required = false, default_value = "300")]
    timeout: u64,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let vault = Vault::load(args.vault_path.clone());
    if let Err(msg) = vault {
        error!("Could not load vault: {}", msg);
        exit(1);
    }

    info!("Successfully loaded vault in {}", args.vault_path.display());
    let vault = vault.unwrap();
    let socket_path = match std::env::home_dir() {
        None => {
            error!("Could not find home directory");
            exit(1)
        }
        Some(home) => home,
    }
    .join(".mpw_socket");
    let _ = std::fs::remove_file(&socket_path); // Remove existing socket if it exists
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            error!(
                "Could not bind socket to {}: '{err}'",
                socket_path.display()
            );
            exit(1);
        }
    };

    let perm = Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(&socket_path, perm) {
        error!("Could not set permissions {e}");
        exit(1);
    }

    info!("Listening on {}...", socket_path.display());
    let handler = Arc::new(request_handler::RequestHandler::new(
        vault,
        Duration::from_secs(args.timeout),
    ));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("got connection from {:?}", stream.peer_addr());
                let handler = Arc::clone(&handler);
                thread::spawn(move || {
                    handler.handle_stream(stream);
                });
            }
            Err(err) => {
                warn!("Could not accept connection: '{err}'");
            }
        }
    }
}
