use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use mpw_core::vault::Vault;
use crate::vault_processor::VaultProcessor;

#[derive(Debug, Args)]
pub struct Load {
    #[arg(required = true)]
    name: String,
    #[arg(short, long, default_value = "false")]
    path: bool,
}

impl Handler for Load {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        if self.path {
            let path = self.name.into();
            Vault::load(path)
        } else {
            let path = match entries.get(&self.name) {
                Some(p) => p,
                None => {
                    println!("No entry with name {}", self.name);
                    return (LoaderState::Select, Followup::None);
                }
            };
            Vault::load(path.to_path_buf())
        }
        .map_or_else(
            |e| {
                println!("Error loading vault: {}", e);
                (LoaderState::Select, Followup::None)
            },
            |vault| (LoaderState::Loaded(VaultProcessor::new(vault)), Followup::None),
        )
    }
}
