use crate::vault_processor::handler::{Followup, Handler};
use crate::vault_processor::{VaultState, util};
use arboard::{Clipboard, LinuxClipboardKind, SetExtLinux};
use clap::Args;
use mpw_core::path_manager::Search;
use mpw_core::vault::Vault;
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
        let candidates = util::list_candidates(self.vault, Search::StartsWith(word), false)?;
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
                if self.show {
                    if let Some(login) = login {
                        println!("{}", login);
                    }
                    println!("{}", pw.unsecure());
                } else {
                    let cb = clipboard.set().clipboard(LinuxClipboardKind::Clipboard);
                    if let Err(e) = cb.text(pw.unsecure()) {
                        eprintln!("Error copying password to clipboard: {}", e.to_string());
                    } else {
                        println!("Password copied to clipboard");
                    }

                    if let Some(login) = login {
                        let cb = clipboard.set().clipboard(LinuxClipboardKind::Primary);
                        if let Err(e) = cb.text(login) {
                            eprintln!("Error copying login to primary: {}", e.to_string());
                        } else {
                            println!("Login copied to primary");
                        }
                    }
                }
            },
        );

        (VaultState::Unlocked, Followup::None)
    }
}
