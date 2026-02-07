use mpw_core::vault::Vault;
use mpw_daemon::messages::{
    Message, MessageType, Query, QueryResult, Response, get, list, status, unlock,
};
use secure_string::SecureString;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

pub struct RequestHandler {
    vault: Mutex<Vault>,
}

macro_rules! generate_handlers {
    ($($variant:ident => $target:ty),* $(,)?) => {
        pub fn reply(msg: &Message, vault: &Mutex<Vault>) -> QueryResult<SecureString> {
            match msg.message_type {
                $(
                MessageType::$variant => {
                    let query = serde_json::from_str::<$target>(msg.payload.unsecure())?;
                    query.generate_response(&vault)
                }
                )*
            }
        }
    };
}

generate_handlers! (
    Status => status::Status,
    Unlock => unlock::Unlock,
    Lock => unlock::Lock,
    Get => get::Get,
    List => list::List,
);

impl RequestHandler {
    pub fn new(vault: Vault) -> Self {
        RequestHandler {
            vault: Mutex::new(vault),
        }
    }

    pub fn handle_stream(&self, stream: UnixStream) {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let line = SecureString::from(line);
        match result {
            Ok(0) => {
                println!("Connection closed by client.");
            }
            Ok(_) => match self.handle_message(line.unsecure()) {
                Ok(response) => {
                    let response = Response::Ok(response);
                    println!("Response: {:?}", response);
                    if let Err(e) = (&stream).write_all(
                        serde_json::to_string(&response)
                            .expect("This should never fail")
                            .as_bytes(),
                    ) {
                        eprintln!("Could not write to socket. {}", e);
                    }
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    let response = Response::Err(e.to_string());
                    if let Err(e) = (&stream).write_all(
                        serde_json::to_string(&response)
                            .expect("This should never fail")
                            .as_bytes(),
                    ) {
                        eprintln!("Could not write to socket. {}", e);
                    }
                }
            },
            Err(err) => {
                eprintln!("Error reading from stream: {}", err);
            }
        }

        if let Err(e) = stream.shutdown(Shutdown::Both) {
            eprintln!("Error shutting down stream: {}", e);
        }
    }

    fn handle_message(&self, data: &str) -> QueryResult<SecureString> {
        let msg: Message = serde_json::from_str(data)?;
        let response = reply(&msg, &self.vault)?;
        Ok(format!("{}\n", response.into_unsecure()).into())
    }
}
