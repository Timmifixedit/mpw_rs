use crate::print_if_error;
use crate::vault_processor::{util, VaultState};
use crate::vault_processor::handler::{Followup, Handler, Verbosity};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;
use rustyline::Context;
use rustyline::completion::{Completer, extract_word};
use std::path::PathBuf;
use crate::vault_processor::enc_dec::print_error;

pub struct ReleaseCompleter<'v> {
    vault: &'v Vault,
}

impl<'v> ReleaseCompleter<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }
}

impl<'v> Completer for ReleaseCompleter<'v> {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        let candidates = util::list_candidates(self.vault, Some(word), true)?;
        Ok((start, candidates))

    }
}

#[derive(Debug, Args)]
#[command(about = "permanently secure a file system entry", long_about = None)]
pub struct Secure {
    #[arg(required = true)]
    name: String,
    #[arg(required = true)]
    path: PathBuf,
}

#[derive(Debug, Args)]
#[command(
    about = "release secured file system entries from vault",
    long_about = "Release secured file system entries from vault. \
    Files are decrypted but not deleted."
)]
pub struct Release {
    #[arg(required = true)]
    names: Vec<String>,
    #[arg(short, long, default_value = "normal")]
    verbose: Verbosity,
}

impl Handler for Secure {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        print_if_error!(vault.add_fs_entry(self.path, self.name));
        (VaultState::Unlocked, Followup::None)
    }
}

impl Handler for Release {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        for name in self.names {
            if let Err(err) = vault.remove_fs_entry(&name) {
                print_error(err, self.verbose.clone());
            }
        }

        (VaultState::Unlocked, Followup::None)
    }
}
