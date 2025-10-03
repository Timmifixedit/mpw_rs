use arboard::Clipboard;
use secure_string::SecureString;
use mpw_core::vault::Vault;
use crate::vault_processor::VaultState;

pub type RawHandler = Box<dyn FnOnce(&mut Vault, String) -> (VaultState, Followup)>;
pub type SecretHandler = Box<dyn FnOnce(&mut Vault, SecureString) -> (VaultState, Followup)>;

pub enum Followup {
    Raw(RawHandler),
    Secret(SecretHandler),
    None,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Normal,
    All,
}

pub trait Handler {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup);
}
