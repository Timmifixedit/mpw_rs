use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;

#[derive(Debug, Args)]
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
