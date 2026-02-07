use crate::messages::{Query, QueryResult};
use clap::Args;
use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Unlock {
    #[arg(required = true)]
    pub master_pw: SecureString,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Lock;

impl Query for Unlock {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<SecureString> {
        let mut vault = vault.lock().expect("Something is seriously wrong");
        vault.unlock(self.master_pw)?;
        Ok("Ok".into())
    }
}

impl Query for Lock {
    fn generate_response(self, vault: &Mutex<Vault>) -> QueryResult<SecureString> {
        let mut vault = vault.lock().expect("Something is seriously wrong");
        vault.lock()?;
        Ok("Ok".into())
    }
}