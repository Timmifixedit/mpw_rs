use clap::{Parser, Subcommand};
use mpw_daemon::messages::{Message, MessageType, Response};
use secure_string::SecureString;
use shellexpand::tilde;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;

#[derive(Debug, Subcommand)]
enum Query {
    #[command(name = "status")]
    Status(mpw_daemon::messages::status::Status),
    #[command(name = "unlock")]
    Unlock(mpw_daemon::messages::unlock::Unlock),
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "MPW Vault Client",
    long_about = "MPW Vault Client: Sends queries to MPW Vault Daemon via UDS"
)]
struct Args {
    #[arg(required = true)]
    socket: String,
    #[clap(subcommand)]
    cmd: Query,
}

macro_rules! generate_to_message {
    ($($variant:ident => $msg_type:expr),* $(,)?) => {
        impl Query {
            pub fn into_message(self) -> Message {
                match self {
                    $(
                    Self::$variant(payload) => Message {
                        message_type: $msg_type,
                        payload: serde_json::to_string(&payload)
                            .expect("Failed to serialize payload")
                            .into(),
                    },
                    )*
                }
            }
        }
    };
}

generate_to_message!(
    Status => MessageType::Status,
    Unlock => MessageType::Unlock,
);

fn send_message(msg: Message, stream: &mut UnixStream) {
    let data = SecureString::from(format!(
        "{}\n",
        serde_json::to_string(&msg).expect("Failed to serialize")
    ));
    if let Err(e) = stream.write_all(data.unsecure().as_bytes()) {
        eprintln!("Failed to send message: {}", e);
        exit(1);
    }
}

fn main() {
    let args = Args::parse();
    let socket = tilde(&args.socket).to_string();
    let mut stream = match UnixStream::connect(&socket) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("Failed to connect to daemon: {}", err);
            exit(1)
        }
    };

    let message = args.cmd.into_message();
    send_message(message, &mut stream);
    let mut response = String::new();
    let res = stream.read_to_string(&mut response);
    match res {
        Ok(0) => {
            println!("Connection closed by server");
            exit(0)
        }
        Err(e) => {
            eprintln!("Failed to read response: {}", e);
            exit(1);
        },
        _ => ()
    }
    let response = SecureString::from(response);
    let response = match serde_json::from_str::<Response>(response.unsecure()) {
        Ok(response) => response,
        Err(err) => {
            eprintln!("Error deserializing response: {err}");
            exit(1);
        }
    };

    match response {
        Response::Ok(data) => {
            println!("{}", data.unsecure())
        }
        Response::Err(err) => {
            eprintln!("{}", err);
        }
    }
}
