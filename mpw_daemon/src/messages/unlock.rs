use crate::messages::{Query, QueryResult};
use clap::Args;
use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Unlock {
    #[arg(required = true)]
    pub master_pw: SecureString,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Lock;

impl Query for Unlock {
    fn generate_response(self, vault: &mut Vault) -> QueryResult<SecureString> {
        vault.unlock(self.master_pw)?;
        Ok("Ok".into())
    }
}

impl Query for Lock {
    fn generate_response(self, vault: &mut Vault) -> QueryResult<SecureString> {
        vault.lock()?;
        Ok("Ok".into())
    }
}