use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct Add {
    #[arg(required = true)]
    name: String,
    #[arg(required = true)]
    path: PathBuf,
    #[arg(short, long, default_value = "false")]
    default: bool,
}

impl Handler for Add {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        entries.add(self.name, self.path, self.default).map_or_else(
            |e| {
                println!("{e}");
            },
            |_| (),
        );
        (LoaderState::Select, Followup::None)
    }
}
