use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub mod status;
pub mod unlock;

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
    Lock
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

//Payload should be serializable (directly via serde, enforce trait) and have a generate_response method
pub trait Query {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<SecureString>;
}
