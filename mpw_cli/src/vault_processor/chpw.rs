use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;

#[derive(Debug, Args)]
#[command(about = "change master password", long_about = None)]
pub struct ChangePw {}

impl Handler for ChangePw {
    fn handle(self, _: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        println!("Enter you new master password:");
        let followup = Followup::Secret(Box::new(move |_, pw1| {
            println!("Enter your new master password again:");
            (
                VaultState::EnterPw,
                Followup::Secret(Box::new(move |vlt, pw2| {
                    if pw1 != pw2 {
                        println!("Passwords do not match");
                        return (VaultState::Unlocked, Followup::None);
                    }

                    vlt.change_master_password(pw1).map_or_else(
                        |e| println!("Failed to change master password: {}", e.to_string()),
                        |_| println!("Successfully changed master password"),
                    );
                    (VaultState::Unlocked, Followup::None)
                })),
            )
        }));
        (VaultState::EnterPw, followup)
    }
}
