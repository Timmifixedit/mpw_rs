use crate::vault_processor::VaultState;
use crate::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::Vault;

#[derive(Debug, Args)]
#[command(about = "retrieve a password", long_about = None)]
pub struct Get {
    #[arg(required = true)]
    pub name: String,

    #[arg(short, long, default_value = "false")]
    pub show: bool,
}

impl Handler<VaultState> for Get {
    fn handle(
        self,
        vault: &mut Vault,
        clipboard: &mut Clipboard,
    ) -> (VaultState, Followup<VaultState>) {
        vault.retrieve_password(&self.name).map_or_else(
            |e| println!("{}", e.to_string()),
            |(pw, login)| {
                if let Some(login) = login {
                    println!("{}", login);
                }
                if self.show {
                    println!("{}", pw.unsecure());
                } else {
                    if let Err(e) = clipboard.set_text(pw.unsecure()) {
                        eprintln!("Error copying password to clipboard: {}", e.to_string());
                    } else {
                        println!("Password copied to clipboard");
                    }
                }
            },
        );

        (VaultState::Unlocked, Followup::None)
    }
}
