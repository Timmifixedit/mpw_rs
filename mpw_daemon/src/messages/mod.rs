use mpw_core::vault::{Vault, VaultError};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use secure_string::SecureString;

pub mod status;
pub mod unlock;

#[derive(thiserror::Error, Debug)]
pub enum ResponseError {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Vault(#[from] VaultError),
}

pub type QueryResult<T> = Result<T, ResponseError>;

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
    Status,
    Unlock,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: SecureString,
}

//Payload should be serializable (directly via serde, enforce trait) and have a generate_response method
pub trait Query {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<String>;
}
