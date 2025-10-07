use crate::print_if_error;
use crate::vault_processor::handler::{Followup, Handler};
use crate::vault_processor::{VaultState, util};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;
use rustyline::Context;
use rustyline::completion::Completer;

pub struct MoveCompleter<'v> {
    vault: &'v Vault,
}

impl<'v> MoveCompleter<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }
}

impl<'v> Completer for MoveCompleter<'v> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) =
            rustyline::completion::extract_word(line, pos, None, |c| c.is_whitespace());
        let words = line
            .split_whitespace()
            .skip(1)
            .filter(|s| !s.starts_with('-'))
            .collect::<Vec<_>>();
        let word_idx = words.iter().position(|s| s.starts_with(word));
        if words.len() > 0 && (word.is_empty() || word_idx.is_none_or(|idx| idx > 0)) {
            return Ok((start, vec![]));
        }

        let search_files = line.split_whitespace().any(|s| s == "-f" || s == "--file");
        let candidates = util::list_candidates(self.vault, Some(word), search_files)?;
        Ok((start, candidates))
    }
}

#[derive(Debug, Args)]
#[command(name = "mv", about = "Rename a password or file")]
pub struct Move {
    #[arg(required = true)]
    source: String,

    #[arg(required = true)]
    destination: String,

    #[arg(short, long, default_value = "false")]
    file: bool,
}

impl Handler for Move {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        print_if_error!(if self.file {
            vault.rename_fs_entry(&self.source, self.destination)
        } else {
            vault.rename_password(&self.source, &self.destination)
        });

        (VaultState::Unlocked, Followup::None)
    }
}
