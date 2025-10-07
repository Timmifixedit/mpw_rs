use mpw_core::vault::Vault;
use mpw_core::vault::VaultError;
use rustyline::error::ReadlineError;

pub fn list_candidates(
    vault: &Vault,
    search: Option<&str>,
    files: bool,
) -> Result<Vec<String>, ReadlineError> {
    if files {
        Ok(vault.list_files(false, search))
    } else {
        match vault.list_passwords(search) {
            Ok(pw_list) => Ok(pw_list),
            Err(VaultError::IoError(e)) => Err(ReadlineError::Io(e)),
            Err(VaultError::VaultLocked) => panic!("Vault is locked"),
            Err(e) => panic!("Unexpected error: {}", e.to_string()),
        }
    }
}
