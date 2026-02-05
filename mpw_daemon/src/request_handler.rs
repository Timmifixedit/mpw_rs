use std::os::unix::net::UnixStream;
use mpw_core::vault::Vault;
use std::sync::Mutex;
use std::io::{BufRead, BufReader};

pub struct RequestHandler {
    vault: Mutex<Vault>,
}

impl RequestHandler {
    pub fn new(vault: Vault) -> Self {
        RequestHandler { vault: Mutex::new(vault) }
    }

    pub fn handle_stream(&self, stream: UnixStream) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    println!("Connection closed.");
                    break;
                }
                Ok(_) => {
                    println!("Received: {}", line.trim());
                }
                Err(err) => {
                    eprintln!("Error reading from stream: {}", err);
                    break;
                }
            }
        }
    }
}
