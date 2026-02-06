use crate::messages::{Message, QueryResult, parse};
use mpw_core::vault::Vault;
use std::io::{BufRead, BufReader};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

pub struct RequestHandler {
    vault: Mutex<Vault>,
}

impl RequestHandler {
    pub fn new(vault: Vault) -> Self {
        RequestHandler {
            vault: Mutex::new(vault),
        }
    }

    pub fn handle_stream(&self, stream: UnixStream) {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    println!("Connection closed.");
                    break;
                }
                Ok(_) => match self.handle_message(&line) {
                    Ok(response) => {
                        println!("Response: {:?}", response);
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        if let Err(e) = stream.shutdown(Shutdown::Both) {
                            eprintln!("Error shutting down stream: {}", e);
                        }
                    }
                },
                Err(err) => {
                    eprintln!("Error reading from stream: {}", err);
                    break;
                }
            }
        }
    }

    fn handle_message(&self, data: &str) -> QueryResult<String> {
        let msg: Message = serde_json::from_str(data)?;
        let query = parse(&msg)?;
        Ok(query.generate_response(&self.vault)?)
    }
}
