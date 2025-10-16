use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use mpw_core::path_manager::Search;
use rustyline::Context;
use rustyline::completion::{Completer, extract_word};

pub struct RemoveCompleter<'e> {
    entries: &'e PathManager,
}

impl<'e> Completer for RemoveCompleter<'e> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        let candidates = self
            .entries
            .list_entries(false, Search::StartsWith(word), false);
        Ok((start, candidates))
    }
}

impl<'e> RemoveCompleter<'e> {
    pub fn new(entries: &'e PathManager) -> Self {
        RemoveCompleter { entries }
    }
}

#[derive(Debug, Args)]
#[command(
    about = "remove a vault from the list",
    long_about = "Remove a vault from the list. \
    The vault is only removed from the list. The actual location is not deleted."
)]
pub struct Remove {
    #[clap(required = true)]
    name: Vec<String>,
}

impl Handler for Remove {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        for name in self.name {
            entries.remove(&name);
        }

        (LoaderState::Select, Followup::None)
    }
}
