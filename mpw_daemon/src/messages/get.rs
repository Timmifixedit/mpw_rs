use crate::messages::{Query, QueryResult};
use clap::Args;
use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Get {
    #[arg(required = true)]
    pub pw: String,
}

impl Query for Get {
    fn generate_response(self, vault: &mut Vault) -> QueryResult<SecureString> {
        let (pw, login) = vault.retrieve_password(&self.pw)?;
        Ok(format!("{}|{}", pw.unsecure(), login.unwrap_or_default()).into())
    }
}
