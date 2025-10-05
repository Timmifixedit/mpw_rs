use crate::print_if_error;
use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::{PathManager, PathManagerError};

#[derive(Debug, Args)]
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
            entries.add(self.destination, path.to_owned(), entries.is_default(&self.source))?;
            Ok::<(), PathManagerError>(entries.remove(&self.source))
        });

        (LoaderState::Select, Followup::None)
    }
}
