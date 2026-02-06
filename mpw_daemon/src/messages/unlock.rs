use std::sync::Mutex;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};
use mpw_core::vault::Vault;
use crate::messages::{Query, QueryResult};

#[derive(Serialize, Deserialize, Debug)]
pub struct Unlock {
    pub master_pw: SecureString,
}

impl Query for Unlock {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<String> {
        let mut vault = vault.lock().expect("Something is seriously wrong");
        vault.unlock(self.master_pw)?;
        Ok("Ok".to_string())
    }
}