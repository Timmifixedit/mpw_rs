use crate::vault_processor::VaultState;
use crate::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;

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

impl Handler<VaultState> for Move {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup<VaultState>) {
        if let Err(res) = if self.file {
            vault.rename_fs_entry(&self.source, self.destination)
        } else {
            vault.rename_password(&self.source, &self.destination)
        } {
            println!("{}", res);
        }

        (VaultState::Unlocked, Followup::None)
    }
}
