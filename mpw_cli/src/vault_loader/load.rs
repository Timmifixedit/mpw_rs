use crate::file_name_completer::FilenameCompleter;
use crate::vault_loader::handler::{Followup, Handler};
use crate::vault_loader::LoaderState;
use crate::vault_processor::VaultProcessor;
use clap::Args;
use mpw_core::path_manager::PathManager;
use mpw_core::vault::{Vault, VaultError};
use rustyline::completion::{extract_word, Completer};
use rustyline::Context;
use std::path::{Path, PathBuf};

pub struct LoadCompleter<'e> {
    entries: &'e PathManager,
    file_completer: FilenameCompleter,
}

impl<'e> Completer for LoadCompleter<'e> {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        let load_path = line.split_whitespace().any(|s| s == "-p" || s == "--path");
        if load_path {
            return self.file_completer.complete(line, pos, ctx);
        }

        let candidates = self.entries.list_entries(false, Some(word), false);
        Ok((start, candidates))
    }
}

impl<'e> LoadCompleter<'e> {
    pub fn new(entries: &'e PathManager) -> Self {
        Self {
            entries,
            file_completer: FilenameCompleter::new(),
        }
    }
}

#[derive(Debug, Args)]
#[command(about = "load a vault from the list or from a path", long_about = None)]
pub struct Load {
    #[arg(required = true)]
    name: String,
    #[arg(short, long, default_value = "false")]
    path: bool,
}

impl Load {
    pub fn new(path: &Path) -> Load {
        Load {
            name: path.to_string_lossy().to_string(),
            path: true,
        }
    }
}

fn create_new_vault(path: PathBuf) -> (LoaderState, Followup) {
    let try_unlock = |mut vault: Vault, pw| -> (LoaderState, Followup) {
        vault.unlock(pw).map_or_else(
            |e| {
                eprintln!("{e}");
                (LoaderState::Select, Followup::None)
            },
            |_| {
                let vp = VaultProcessor::new(vault);
                println!("Successfully created a new vault. Vault is now unlocked.");
                (LoaderState::Loaded(vp), Followup::None)
            },
        )
    };

    let create = move |pw1, pw2| -> (LoaderState, Followup) {
        if pw1 != pw2 {
            println!("Passwords do not match");
            return (LoaderState::Select, Followup::None);
        }

        Vault::new(path, pw1).map_or_else(
            |e| {
                println!("{e}");
                (LoaderState::Select, Followup::None)
            },
            |vault| try_unlock(vault, pw2),
        )
    };

    let ask_pw = |pw1| -> (LoaderState, Followup) {
        println!("Please enter your master password again");
        (
            LoaderState::Secret,
            Followup::Secret(Box::new(move |pw2| create(pw1, pw2))),
        )
    };

    println!("Creating a new vault. Please enter your master password");
    (
        LoaderState::Secret,
        Followup::Secret(Box::new(move |pw1| ask_pw(pw1))),
    )
}

impl Handler for Load {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        let path = if self.path {
            Path::new(&self.name)
        } else {
            let path = match entries.get(&self.name) {
                Some(p) => p,
                None => {
                    println!("No entry with name {}", self.name);
                    return (LoaderState::Select, Followup::None);
                }
            };
            path
        };

        Vault::load(path.to_owned()).map_or_else(
            |e| {
                if let VaultError::VaultFileNotFound(_) = &e {
                    create_new_vault(path.to_owned())
                } else {
                    println!("Error loading vault: {}", e);
                    (LoaderState::Select, Followup::None)
                }
            },
            |vault| {
                let vp = VaultProcessor::new(vault);
                println!(
                    "Loaded vault {}{}",
                    if self.path { "at " } else { "" },
                    self.name
                );
                (LoaderState::Loaded(vp), Followup::None)
            },
        )
    }
}
