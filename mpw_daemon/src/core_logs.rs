use crate::core_logs::Severity::{Error, Info, Warn};
use crate::messages::VaultError;
use log::{error, info, warn};
use mpw_core::error::MpwError;
use mpw_core::vault::{EncryptionNoOp, VaultError as CoreError};

#[derive(PartialOrd, PartialEq, Eq, Ord)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

pub fn vault_error_severity(err: &CoreError) -> Severity {
    match err {
        CoreError::Fatal(_) | CoreError::IoError(_) => Error,

        CoreError::PasswordError(_)
        | CoreError::InvalidParameter(_)
        | CoreError::ItemSkipped(EncryptionNoOp::VaultItem { .. })
        | CoreError::VaultLocked
        | CoreError::PathManagerError(_)
        | CoreError::ItemSkipped(EncryptionNoOp::ProtectedItem(_)) => Warn,

        CoreError::ItemSkipped(EncryptionNoOp::NotEncrypted(_))
        | CoreError::ItemSkipped(EncryptionNoOp::AlreadyEncrypted(_)) => Info,

        CoreError::CoreError(e) => match e {
            MpwError::IoError(_)
            | MpwError::Cryptography(_)
            | MpwError::InvalidHeader(_)
            | MpwError::InvalidKeyLength { .. }
            | MpwError::InvalidUtf8(_) => Error,

            MpwError::WrongPassword => Error,
        },
    }
}

pub fn log(severity: Severity, err: &CoreError) {
    match severity {
        Error => error!("{err}"),
        Warn => warn!("{err}"),
        Info => info!("{err}"),
    }
}

pub fn log_vault_errors(err: &VaultError, severity: Severity) {
    match err {
        VaultError::Simple(e) => {
            log(vault_error_severity(e), e);
        }
        VaultError::Stack(e) => {
            for ve in &e.errors {
                let sev = vault_error_severity(ve);
                if sev >= severity {
                    log(sev, ve);
                }
            }
        }
    }
}
