use crate::messages::{Query, QueryResult};
use clap::Args;
use mpw_core::vault::Vault;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Args)]
pub struct Status {}

impl Query for Status {
    fn generate_response(self, vault: &mut Vault) -> QueryResult<SecureString> {
        Ok(if vault.is_locked() {
            "locked"
        } else {
            "unlocked"
        }
        .into())
    }
}
