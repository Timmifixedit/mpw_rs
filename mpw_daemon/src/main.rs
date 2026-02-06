mod request_handler;

use clap::Parser;
use mpw_core::vault::Vault;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::thread;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "MPW Vault Daemon",
    long_about = "MPW Vault Daemon: Manages a vault and provides an interface via UDS"
)]
struct Args {
    #[arg(required = true)]
    vault_path: PathBuf,
}

fn main() {
    let args = Args::parse();
    let vault = Vault::load(args.vault_path.clone());
    if let Err(msg) = vault {
        eprintln!("Could not load vault: {}", msg);
        exit(1);
    }

    println!("Successfully loaded vault in {}", args.vault_path.display());
    let vault = vault.unwrap();
    let socket_path = "/home/tim/.mpw_socket";
    let _ = std::fs::remove_file(socket_path); // Remove existing socket if it exists
    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Could not bind socket to {socket_path}: '{err}'");
            exit(1);
        }
    };

    let perm = Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(socket_path, perm) {
        eprintln!("Could not set permissions {e}");
        exit(1);
    }

    println!("Listening on {socket_path}...");
    let handler = Arc::new(request_handler::RequestHandler::new(vault));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("got connection from {:?}", stream.peer_addr());
                let handler = Arc::clone(&handler);
                thread::spawn(move || {
                    handler.handle_stream(stream);
                });
            }
            Err(err) => {
                eprintln!("Could not accept connection: '{err}'");
            }
        }
    }
}
