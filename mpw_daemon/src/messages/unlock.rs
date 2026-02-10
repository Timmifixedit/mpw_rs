use crate::core_logs::{vault_error_severity, Severity};
use crate::messages::{Query, QueryResult, Shared};
use clap::Args;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Unlock {
    pub master_pw: SecureString,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct Lock;

impl Query for Unlock {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString> {
        shared.vault.unlock(self.master_pw)?;
        Ok("Ok".into())
    }
}

impl Query for Lock {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString> {
        if let Err(err) = shared.vault.lock() {
            let severe = err
                .errors
                .iter()
                .filter(|e| vault_error_severity(e) > Severity::Info)
                .count();
            if severe == 0 {
                Ok("Ok".into())
            } else {
                Err(err.into())
            }
        } else {
            Ok("Ok".into())
        }
    }
}
