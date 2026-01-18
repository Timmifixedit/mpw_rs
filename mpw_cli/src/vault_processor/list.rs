use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::path_manager::Search;
use mpw_core::vault::Vault;

#[derive(Debug, Args)]
#[command(about = "list all passwords / files", long_about = None)]
pub struct List {
    #[arg(required = false, default_value = None)]
    pub search: Option<String>,

    #[arg(short, long, default_value = "false")]
    pub path: bool,

    #[arg(short, long, default_value = "false")]
    pub files: bool,
}

impl Handler for List {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let mut entries;
        let search = self
            .search
            .as_deref()
            .map_or_else(|| Search::None, |s| Search::Contains(s));
        if self.files {
            entries = vault.list_files(self.path, search);
        } else {
            entries = vault.list_passwords(search).unwrap_or_else(|e| {
                println!("{}", e.to_string());
                vec![]
            })
        }

        entries.sort();
        for entry in entries {
            println!("{}", entry);
        }
        (VaultState::Unlocked, Followup::None)
    }
}
