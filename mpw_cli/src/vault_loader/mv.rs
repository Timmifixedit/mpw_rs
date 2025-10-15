use crate::print_if_error;
use crate::util::current_arg_idx;
use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::{PathManager, PathManagerError};
use rustyline::Context;
use rustyline::completion::Completer;

pub struct MoveCompleter<'e> {
    entries: &'e PathManager,
}

impl<'e> MoveCompleter<'e> {
    pub fn new(entries: &'e PathManager) -> Self {
        MoveCompleter { entries }
    }
}

impl<'e> Completer for MoveCompleter<'e> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) =
            rustyline::completion::extract_word(line, pos, None, |c| c.is_whitespace());
        if current_arg_idx(pos, line) > 1 {
            // first word is command
            return Ok((start, vec![]));
        }

        let candidates = self.entries.list_entries(false, Some(word), false);
        Ok((start, candidates))
    }
}

#[derive(Debug, Args)]
#[command(about = "move (rename) a saved vault", long_about = None)]
pub struct Move {
    #[arg(required = true)]
    source: String,

    #[arg(required = true)]
    destination: String,
}

impl Handler for Move {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        print_if_error!({
            let path = entries
                .get(&self.source)
                .ok_or(PathManagerError::EntryNotFound(self.source.clone()))?;
            entries.add(
                self.destination,
                path.to_owned(),
                entries.is_default(&self.source),
            )?;
            Ok::<(), PathManagerError>(entries.remove(&self.source))
        });

        (LoaderState::Select, Followup::None)
    }
}
