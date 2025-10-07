use crate::vault_processor::handler::{Followup, Handler};
use crate::vault_processor::{VaultState, util};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault;
use mpw_core::vault::{Vault, VaultError};
use rustyline::completion::{Completer, extract_word};
use std::num::NonZeroU32;

pub struct AddCompleter<'v> {
    vault: &'v Vault,
}

impl<'v> AddCompleter<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        AddCompleter { vault }
    }
}

impl<'v> Completer for AddCompleter<'v> {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        if !line
            .split_whitespace()
            .any(|s| s == "-o" || s == "--overwrite")
        {
            return Ok((start, vec![]));
        }

        let candidates = util::list_candidates(self.vault, Some(word), false)?;
        Ok((start, candidates))
    }
}

#[derive(Debug, Args)]
#[command(about = "add a password", long_about = None)]
pub struct Add {
    #[arg(required = true)]
    pub name: String,

    #[arg(short, long, default_value = None)]
    pub rand_len: Option<NonZeroU32>,

    #[arg(short, long, default_value = None)]
    pub invalid_chars: Option<String>,

    #[arg(short, long, default_value = "false")]
    pub overwrite: bool,

    #[arg(short, long, default_value = None)]
    pub login: Option<String>,
}

impl Handler for Add {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let result = (|| {
            let exists = vault.list_passwords(None)?.contains(&self.name);
            if exists && !self.overwrite {
                return Err(VaultError::AlreadyExists(self.name.clone()));
            }

            if self.overwrite && !exists {
                return Err(VaultError::PasswordNotFound(self.name.clone()));
            }

            let success_msg = format!(
                "Successfully {} password {}",
                if self.overwrite { "updated" } else { "created" },
                self.name
            );

            if let Some(r_len) = self.rand_len {
                let pw = vault::random_password(r_len, self.invalid_chars.as_deref())?;
                vault.write_password(&self.name, pw, self.login.as_deref(), self.overwrite)?;
                println!("{}", success_msg);
                return Ok((VaultState::Unlocked, Followup::None));
            }

            println!("Enter password:");
            let followup = Followup::Secret(Box::new(move |vlt, pw| {
                println!(
                    "{}",
                    vlt.write_password(
                        self.name.as_str(),
                        pw,
                        self.login.as_deref(),
                        self.overwrite,
                    )
                    .map_or_else(|e| e.to_string(), |_| success_msg)
                );
                (VaultState::Unlocked, Followup::None)
            }));

            Ok((VaultState::EnterPw, followup))
        })();
        result.unwrap_or_else(|e| {
            println!("{}", e.to_string());
            (VaultState::Unlocked, Followup::None)
        })
    }
}
