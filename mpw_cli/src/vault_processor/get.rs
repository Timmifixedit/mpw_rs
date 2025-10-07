use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::{Vault, VaultError};
use rustyline::Context;
use rustyline::completion::{Completer, extract_word};

pub struct GetCompleter<'v> {
    vault: &'v Vault,
}

impl<'v> GetCompleter<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }
}

impl<'v> Completer for GetCompleter<'v> {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        let candidates = match self.vault.list_passwords(Some(word)) {
            Ok(pw_list) => pw_list,
            Err(VaultError::IoError(e)) => return Err(rustyline::error::ReadlineError::Io(e)),
            Err(VaultError::VaultLocked) => panic!("Vault is locked"),
            Err(e) => panic!("Unexpected error: {}", e.to_string()),
        };

        Ok((start, candidates))
    }
}

#[derive(Debug, Args)]
#[command(about = "retrieve a password", long_about = None)]
pub struct Get {
    #[arg(required = true)]
    pub name: String,

    #[arg(short, long, default_value = "false")]
    pub show: bool,
}

impl Handler for Get {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        vault.retrieve_password(&self.name).map_or_else(
            |e| println!("{}", e.to_string()),
            |(pw, login)| {
                if let Some(login) = login {
                    println!("{}", login);
                }
                if self.show {
                    println!("{}", pw.unsecure());
                } else {
                    if let Err(e) = clipboard.set_text(pw.unsecure()) {
                        eprintln!("Error copying password to clipboard: {}", e.to_string());
                    } else {
                        println!("Password copied to clipboard");
                    }
                }
            },
        );

        (VaultState::Unlocked, Followup::None)
    }
}
