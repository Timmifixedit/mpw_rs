use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use mpw_core::path_manager::Search;

#[derive(Debug, Args)]
#[command(about = "list known vaults", long_about = None)]
pub struct List {
    #[arg(required = false, default_value = None)]
    search: Option<String>,

    #[arg(short, long, default_value = "false")]
    path: bool,
}

impl Handler for List {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        let content = entries.list_entries(
            self.path,
            self.search
                .as_ref()
                .map_or_else(|| Search::None, |s| Search::Contains(s)),
            true,
        );
        for entry in content {
            println!("{}", entry);
        }

        (LoaderState::Select, Followup::None)
    }
}
