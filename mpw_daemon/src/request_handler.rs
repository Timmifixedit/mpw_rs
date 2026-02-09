use log::{debug, error, warn};
use mpw_core::vault::Vault;
use mpw_daemon::core_logs;
use mpw_daemon::core_logs::Severity;
use mpw_daemon::messages::{
    Message, MessageType, Query, QueryResult, Response, ResponseError, get, list, status, unlock,
};
use mpw_daemon::timer::CancellationToken;
use secure_string::SecureString;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::ops::DerefMut;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct RequestHandler {
    vault: Arc<Mutex<Vault>>,
    timer: Mutex<CancellationToken>,
    timeout: Duration,
}

macro_rules! generate_handlers {
    ($($variant:ident => $target:ty),* $(,)?) => {
        pub fn reply(msg: &Message, vault: &mut Vault) -> QueryResult<SecureString> {
            match msg.message_type {
                $(
                MessageType::$variant => {
                    let query = serde_json::from_str::<$target>(msg.payload.unsecure())?;
                    query.generate_response(vault)
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
    pub fn new(vault: Vault, lock_timeout: Duration) -> Self {
        let vault = Arc::new(Mutex::new(vault));
        RequestHandler {
            vault,
            timer: Mutex::new(CancellationToken::new()),
            timeout: lock_timeout,
        }
    }

    fn reset_timeout(&self) {
        debug!("Resetting lock timeout");
        let vault_clone = self.vault.clone();
        let mut timer_access = self.timer.lock().unwrap();
        timer_access.cancel();
        *timer_access = CancellationToken::launch(
            move || {
                if let Ok(mut v) = vault_clone.lock()
                    && !v.is_locked()
                {
                    debug!("Lock timeout reached. Locking vault.");
                    if let Err(e) = v.lock() {
                        core_logs::log_vault_errors(&e.into(), Severity::Warn);
                    }
                }
            },
            self.timeout,
        );
    }

    pub fn handle_stream(&self, stream: UnixStream) {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let line = SecureString::from(line);
        match result {
            Ok(0) => {
                warn!("Connection closed by client.");
            }
            Ok(_) => match self.handle_message(line.unsecure()) {
                Ok(response) => {
                    let response = Response::Ok(response);
                    debug!("Response: {:?}", response);
                    if let Err(e) = (&stream).write_all(
                        serde_json::to_string(&response)
                            .expect("This should never fail")
                            .as_bytes(),
                    ) {
                        error!("Could not write to socket. {}", e);
                    }
                }
                Err(e) => {
                    match &e {
                        ResponseError::Serde(_) => {
                            error! {"Serialization error: {e}"}
                        }
                        ResponseError::Vault(ve) => core_logs::log_vault_errors(ve, Severity::Info),
                    }
                    let response = Response::Err(e.to_string());
                    if let Err(e) = (&stream).write_all(
                        serde_json::to_string(&response)
                            .expect("This should never fail")
                            .as_bytes(),
                    ) {
                        error!("Could not write to socket. {}", e);
                    }
                }
            },
            Err(err) => {
                error!("Error reading from stream: {}", err);
            }
        }

        if let Err(e) = stream.shutdown(Shutdown::Both) {
            error!("Error shutting down stream: {}", e);
        }
    }

    fn handle_message(&self, data: &str) -> QueryResult<SecureString> {
        let mut vault = self.vault.lock().unwrap_or_else(|err| {
            warn!("A handler panicked: {}", err);
            err.into_inner()
        });
        let msg: Message = serde_json::from_str(data)?;
        let response = reply(&msg, vault.deref_mut())?;
        match msg.message_type {
            MessageType::List | MessageType::Get | MessageType::Unlock => self.reset_timeout(),
            _ => (),
        }

        Ok(format!("{}\n", response.into_unsecure()).into())
    }
}
