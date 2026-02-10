use crate::messages::{Query, QueryResult, Shared};
use clap::Args;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Args)]
pub struct Status {}

impl Query for Status {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString> {
        Ok(if shared.vault.is_locked() {
            "locked"
        } else {
            "unlocked"
        }
        .into())
    }
}
