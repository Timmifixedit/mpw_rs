use arboard::Clipboard;
use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

pub mod status;
pub mod unlock;
pub mod get;
pub mod list;

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error(transparent)]
    Simple(#[from] mpw_core::vault::VaultError),
    #[error(transparent)]
    Stack(#[from] mpw_core::vault::VaultErrorStack),
}

#[derive(thiserror::Error, Debug)]
pub enum ResponseError {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl From<mpw_core::vault::VaultError> for ResponseError {
    fn from(e: mpw_core::vault::VaultError) -> Self {
        ResponseError::Vault(e.into())
    }
}

impl From<mpw_core::vault::VaultErrorStack> for ResponseError {
    fn from(value: mpw_core::vault::VaultErrorStack) -> Self {
        ResponseError::Vault(value.into())
    }
}

pub type QueryResult<T> = Result<T, ResponseError>;

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
    Status,
    Unlock,
    Lock,
    Get,
    List
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: SecureString,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Ok(SecureString),
    Err(String),
}

pub struct Shared {
    pub vault: Vault,
    pub clipboard: Clipboard,
}

pub trait Query {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString>;
}
