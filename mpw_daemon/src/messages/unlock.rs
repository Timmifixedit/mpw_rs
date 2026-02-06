use std::sync::Mutex;
use clap::{Args};
use secure_string::SecureString;
use serde::{Deserialize, Serialize};
use mpw_core::vault::Vault;
use crate::messages::{Query, QueryResult};

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Unlock {
    #[arg(required = true)]
    pub master_pw: SecureString,
}

impl Query for Unlock {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<SecureString> {
        let mut vault = vault.lock().expect("Something is seriously wrong");
        vault.unlock(self.master_pw)?;
        Ok("Ok".into())
    }
}