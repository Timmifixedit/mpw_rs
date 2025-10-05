use crate::vault_loader::LoaderState;
use crate::vault_loader::handler::{Followup, Handler};
use clap::Args;
use mpw_core::path_manager::PathManager;
use std::path::PathBuf;

macro_rules! print_if_error {
    ($expr:expr) => {
        let run = || -> Result<_, _> { $expr };
        if let Err(e) = run() {
            println!("{e}");
        }
    };
}

#[derive(Debug, Args)]
pub struct Add {
    #[arg(required = true)]
    name: String,
    #[arg(required = false, default_value = None)]
    path: Option<PathBuf>,
    #[arg(short, long, default_value = "false")]
    default: bool,
    #[arg(short, long, default_value = "false")]
    overwrite: bool,
}

impl Handler for Add {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        if self.overwrite {
            print_if_error!({
                if let Some(path) = self.path {
                    entries.update(&self.name, path)?;
                }
                entries.update_default(&self.name, self.default)
            });
        } else {
            if let Some(path) = self.path {
                print_if_error!(entries.add(self.name, path, self.default));
            } else {
                println!("Please specify a path to add.");
            };
        }

        (LoaderState::Select, Followup::None)
    }
}
