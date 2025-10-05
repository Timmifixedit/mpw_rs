use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;

#[derive(Debug, Args)]
#[command(about = "remove passwords", long_about = None)]
pub struct Remove {
    #[arg(required = true)]
    pub names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    pub yes: bool,
}

impl Handler for Remove {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let remove = move |vlt: &mut Vault| {
            for name in self.names {
                vlt.delete_password(&name).map_or_else(
                    |e| println!("failed to delete password {}: {}", name, e.to_string()),
                    |_| println!("Successfully deleted password {}", name),
                );
            }
        };

        if !self.yes {
            println!("Please confirm the deletion of the passwords (type 'yes' to confirm)");
            (
                VaultState::RawInput,
                Followup::Raw(Box::new(move |vlt, cmd| {
                    if cmd != "yes" {
                        println!("Aborted. Type 'yes' to confirm removal");
                        return (VaultState::Unlocked, Followup::None);
                    }

                    remove(vlt);
                    (VaultState::Unlocked, Followup::None)
                })),
            )
        } else {
            remove(vault);
            (VaultState::Unlocked, Followup::None)
        }
    }
}
