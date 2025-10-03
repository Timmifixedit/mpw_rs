use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler};
use arboard::Clipboard;
use clap::Args;
use mpw_core::error::MpwError;
use mpw_core::vault::{Vault, VaultError};
use secure_string::SecureString;
use std::process::exit;

#[derive(Debug, Args)]
#[command(about = "lock the vault", long_about = None)]
pub struct Lock {}

pub fn unlock(vault: &mut Vault, master_pw: SecureString) -> (VaultState, Followup) {
    type V = VaultError;
    match vault.unlock(master_pw) {
        Ok(_) => (VaultState::Unlocked, Followup::None),
        Err(err) => match err {
            V::VaultDirNotFound(e) | V::VaultFileNotFound(e) => {
                eprintln!("Fatal error: {e}");
                exit(1);
            }
            V::IoError(e) => {
                eprintln!("Fatal error: {e}");
                exit(1);
            }

            V::CoreError(e) => match e {
                MpwError::WrongPassword => {
                    println!("Wrong password");
                    (
                        VaultState::Locked,
                        Followup::Secret(Box::new(|vault, pw| unlock(vault, pw))),
                    )
                }
                e => {
                    eprintln!("Fatal error: {e}");
                    exit(1);
                }
            },

            V::VaultLocked
            | V::PasswordNotFound(_)
            | V::InvalidPwName(_)
            | V::AlreadyExists(_)
            | V::InvalidParameter(_)
            | V::VaultItem { .. }
            | V::ProtectedItem(_)
            | V::AlreadyEncrypted(_)
            | V::NotEncrypted(_)
            | V::PathManagerError(_) => {
                panic!("Unexpected error: {}", err);
            }
        },
    }
}

impl Handler for Lock {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        type V = VaultError;
        if let Err(err) = clipboard.clear() {
            println!("Error clearing clipboard: {err}");
        }

        if let Err(err) = vault.lock() {
            for e in err.errors {
                match e {
                    V::NotEncrypted(_)
                    | V::VaultLocked
                    | V::InvalidParameter(_)
                    | V::InvalidPwName(_)
                    | V::PasswordNotFound(_) => {
                        panic!("Unexpected error: {}", e);
                    }

                    V::AlreadyEncrypted(_) => {}

                    V::VaultDirNotFound(e)
                    | V::VaultFileNotFound(e)
                    | V::AlreadyExists(e)
                    | V::ProtectedItem(e) => println!("{e}"),
                    V::PathManagerError(_) => println!("{e}"),
                    V::IoError(e) => println!("{e}"),
                    V::CoreError(e) => println!("{e}"),
                    V::VaultItem {
                        item: i,
                        vault_dir: v,
                    } => println!("{i} is a protected item within the vault directory {v}"),
                }
            }
        }
        (
            VaultState::Locked,
            Followup::Secret(Box::new(|vault, pw| unlock(vault, pw))),
        )
    }
}
