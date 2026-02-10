use arboard::{LinuxClipboardKind, SetExtLinux};
use crate::messages::{Query, QueryResult, Shared};
use clap::Args;
use log::{debug, error};
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Get {
    #[arg(required = true)]
    pub pw: String,
    #[arg(long, default_value = "false")]
    pub send_back: bool,
}

impl Query for Get {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString> {
        let (pw, login) = shared.vault.retrieve_password(&self.pw)?;
        if self.send_back {
            return Ok(format!("{}|{}", pw.unsecure(), login.unwrap_or_default()).into());
        }

        let cb = shared.clipboard.set().clipboard(LinuxClipboardKind::Clipboard);
        if let Err(e) = cb.text(pw.unsecure()) {
            error!("Error copying password to clipboard: {}", e.to_string());
        } else {
            debug!("Password copied to clipboard");
        }

        let cb = shared.clipboard.set().clipboard(LinuxClipboardKind::Primary);
        if let Err(e) = cb.text(login.unwrap_or_default()) {
            error!("Error copying login to primary: {}", e.to_string());
        } else {
            debug!("Login copied to clipboard");
        }

        Ok("Copied password to clipboard".into())
    }
}
