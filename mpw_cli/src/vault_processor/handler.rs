use crate::vault_processor::VaultState;
use arboard::Clipboard;
use mpw_core::vault::Vault;
use secure_string::SecureString;

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
