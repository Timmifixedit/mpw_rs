use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler, Verbosity};
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::{Vault, VaultErrorStack};
use std::path::PathBuf;
use crate::print_if_error;

#[derive(Debug, Args)]
#[command(about = "permanently secure a file system entry", long_about = None)]
pub struct Secure {
    #[arg(required = true)]
    name: String,
    #[arg(required = true)]
    path: PathBuf,
}

#[derive(Debug, Args)]
#[command(about = "release secured file system entries from vault", long_about = None)]
pub struct Release {
    #[arg(required = true)]
    names: Vec<String>,
    #[arg(short, long, default_value = "normal")]
    verbose: Verbosity,
}

impl Handler for Secure {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        print_if_error!(vault.add_fs_entry(self.path, self.name));
        (VaultState::Unlocked, Followup::None)
    }
}

impl Handler for Release {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        for name in self.names {
            if let Err(err) = vault.remove_fs_entry(&name) {
                match &self.verbose {
                    Verbosity::Quiet => {}
                    Verbosity::Normal => {
                        println!("Errors during file decryption for entry {name}:");
                    }
                    Verbosity::All => {
                        println!("Errors during file decryption for entry {name}: {err}");
                    }
                }
            }
        }

        (VaultState::Unlocked, Followup::None)
    }
}
