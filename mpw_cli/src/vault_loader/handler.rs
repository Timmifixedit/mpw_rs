use crate::vault_loader::LoaderState;
use mpw_core::path_manager::PathManager;
use secure_string::SecureString;

pub type SecretHandler = Box<dyn FnOnce(SecureString) -> (LoaderState, Followup)>;

pub enum Followup {
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
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup);
}
