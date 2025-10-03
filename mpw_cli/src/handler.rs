use arboard::Clipboard;
use secure_string::SecureString;
use mpw_core::vault::Vault;

pub type RawHandler<T> = Box<dyn FnOnce(&mut Vault, String) -> (T, Followup<T>)>;
pub type SecretHandler<T> = Box<dyn FnOnce(&mut Vault, SecureString) -> (T, Followup<T>)>;

pub enum Followup<T> {
    Raw(RawHandler<T>),
    Secret(SecretHandler<T>),
    None,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Normal,
    All,
}

pub trait Handler<T> {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (T, Followup<T>);
}
