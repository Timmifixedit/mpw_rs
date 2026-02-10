use crate::messages::{Query, QueryResult, Shared};
use clap::Args;
use mpw_core::path_manager::Search;
use secure_string::SecureString;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct List {
    #[arg(required = false, default_value = None)]
    pub search: Option<String>,
    #[arg(short, long, required = false, default_value = "false")]
    files: bool,
    #[arg(short, long, required = false, default_value = "false")]
    path: bool,
}

impl Query for List {
    fn generate_response(self, shared: &mut Shared) -> QueryResult<SecureString> {
        let search = self
            .search
            .as_deref()
            .map_or_else(|| Search::None, |s| Search::Contains(s));
        let result = if self.files {
            shared.vault.list_files(self.path, search)
        } else {
            shared.vault.list_passwords(search)?
        };

        Ok(SecureString::from(result.join("\n")))
    }
}
