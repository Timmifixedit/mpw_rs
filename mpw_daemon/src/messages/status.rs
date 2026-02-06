use crate::messages::{Query, QueryResult};
use mpw_core::vault::Vault;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReply {
    locked: bool,
}

impl Query for Status {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<String> {
        let vault = vault.lock().expect("Something is seriously wrong");
        Ok(serde_json::ser::to_string(&StatusReply {
            locked: vault.is_locked(),
        })?)
    }
}
