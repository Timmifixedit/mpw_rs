use mpw_core::vault::{Vault, VaultError};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub mod status;

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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    message_type: MessageType,
    payload: String,
}

pub fn parse(msg: &Message) -> Result<Box<dyn Query>, serde_json::Error> {
    match msg.message_type {
        MessageType::Status => {
            let query: status::Status = serde_json::from_str(msg.payload.as_str())?;
            Ok(Box::new(query))
        }
    }
}

//Payload should be serializable (directly via serde, enforce trait) and have a generate_response method
pub trait Query {
    fn generate_response(&self, vault: &Mutex<Vault>) -> QueryResult<String>;
}
