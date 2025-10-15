use crate::print_if_error;
use crate::util::current_arg_idx;
use crate::vault_processor::enc_dec::print_error;
use crate::vault_processor::handler::{Followup, Handler, Verbosity};
use crate::vault_processor::{VaultState, util};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;
use rustyline::Context;
use rustyline::completion::{Completer, FilenameCompleter, extract_word};
use std::path::PathBuf;

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

pub struct SecureCompleter {
    file_completer: FilenameCompleter,
}

impl SecureCompleter {
    pub fn new() -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
        }
    }
}

impl Completer for SecureCompleter {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        if current_arg_idx(pos, line) < 2 {
            return Ok((0, vec![]));
        }

        self.file_completer
            .complete(line, pos, ctx)
            .map(|(s, c)| (s, c.into_iter().map(|p| p.replacement).collect()))
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
