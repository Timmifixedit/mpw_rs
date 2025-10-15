use crate::file_name_completer::FilenameCompleter;
use crate::vault_processor::VaultState;
use crate::vault_processor::handler::{Followup, Handler, Verbosity};
use crate::vault_processor::util::list_candidates;
use arboard::Clipboard;
use clap::Args;
use mpw_core::vault::{Vault, VaultError, VaultErrorStack};
use rustyline::Context;
use rustyline::completion::{Completer, extract_word};
use std::path::Path;

pub struct EncDecCompleter<'v> {
    vault: &'v Vault,
    file_completer: FilenameCompleter,
}

impl<'v> EncDecCompleter<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self {
            vault,
            file_completer: FilenameCompleter::new(),
        }
    }
}

impl<'v> Completer for EncDecCompleter<'v> {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, word) = extract_word(line, pos, None, |c| c.is_whitespace());
        if !line.split_whitespace().any(|s| s == "-p" || s == "--path") {
            let candidates = list_candidates(self.vault, Some(word), true)?;
            return Ok((start, candidates));
        }
        self.file_completer.complete(line, pos, ctx)
    }
}

#[derive(Debug, Args)]
#[command(about = "encrypt file system entries", long_about = None)]
pub struct Enc {
    #[arg(required = true)]
    names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    path: bool,

    #[arg(short, long, default_value = "normal")]
    verbose: Verbosity,

    #[arg(short, long, default_value = "false")]
    recursive: bool,
}

#[derive(Debug, Args)]
#[command(about = "decrypt file system entries", long_about = None)]
pub struct Dec {
    #[arg(required = true)]
    names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    path: bool,

    #[arg(short, long, default_value = "normal")]
    verbose: Verbosity,

    #[arg(short, long, default_value = "false")]
    recursive: bool,
}

pub fn print_error(err: VaultErrorStack, verbose: Verbosity) {
    if verbose == Verbosity::Quiet {
        return;
    }

    for e in err.errors {
        match e {
            VaultError::VaultLocked
            | VaultError::InvalidPwName(_)
            | VaultError::InvalidParameter(_)
            | VaultError::PasswordNotFound(_) => {
                panic!("unexpected error {e:?}")
            }

            VaultError::VaultDirNotFound(_) | VaultError::VaultFileNotFound(_) => {
                eprintln!("Critical error: {e}")
            }

            VaultError::PathManagerError(_) => println!("{e}"),

            VaultError::NotEncrypted(_) | VaultError::AlreadyEncrypted(_) => {
                if verbose == Verbosity::All {
                    println!("{e}");
                }
            }

            VaultError::IoError(_)
            | VaultError::CoreError(_)
            | VaultError::ProtectedItem(_)
            | VaultError::AlreadyExists(_) => {
                if verbose >= Verbosity::Normal {
                    println!("{e}");
                }
            }

            VaultError::VaultItem { .. } => {
                if verbose >= Verbosity::Normal {
                    println!("{e}");
                }
            }
        }
    }
}

trait FsHandler {
    fn process_file(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack>;
    fn process_dir(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack>;
    fn process_name(&self, vault: &mut Vault, name: &str) -> Result<(), VaultErrorStack>;
    fn get_names(&self) -> &[String];
    fn is_path(&self) -> bool;
    fn get_verbosity(&self) -> Verbosity;
    fn is_recursive(&self) -> bool;
    fn get_name(&self) -> &str;

    fn process(&self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let mut process = |name| {
            if self.is_path() {
                let path = Path::new(name);
                if path.is_dir() && !self.is_recursive() {
                    println!("{name} is a directory. Use the recursive flag");
                    return Ok(());
                }
                if path.is_dir() {
                    self.process_dir(vault, path)
                } else {
                    self.process_file(vault, path)
                }
            } else {
                self.process_name(vault, name)
            }
        };

        println!("File {}ion in progress. Please wait...", self.get_name());
        for name in self.get_names() {
            if let Err(err) = process(name) {
                print_error(err, self.get_verbosity());
            }
        }

        (VaultState::Unlocked, Followup::None)
    }
}

impl FsHandler for Enc {
    fn process_file(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack> {
        vault.encrypt_file(path).map_err(|e| e.into())
    }

    fn process_dir(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack> {
        vault.encrypt_directory(path)
    }

    fn process_name(&self, vault: &mut Vault, name: &str) -> Result<(), VaultErrorStack> {
        vault.encrypt_by_name(name)
    }

    fn get_names(&self) -> &[String] {
        self.names.as_slice()
    }

    fn is_path(&self) -> bool {
        self.path
    }

    fn get_verbosity(&self) -> Verbosity {
        self.verbose.clone()
    }

    fn is_recursive(&self) -> bool {
        self.recursive
    }

    fn get_name(&self) -> &str {
        "encrypt"
    }
}

impl FsHandler for Dec {
    fn process_file(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack> {
        vault.decrypt_file(path).map_err(|e| e.into())
    }

    fn process_dir(&self, vault: &mut Vault, path: &Path) -> Result<(), VaultErrorStack> {
        vault.decrypt_directory(path)
    }

    fn process_name(&self, vault: &mut Vault, name: &str) -> Result<(), VaultErrorStack> {
        vault.decrypt_by_name(name)
    }

    fn get_names(&self) -> &[String] {
        self.names.as_slice()
    }

    fn is_path(&self) -> bool {
        self.path
    }

    fn get_verbosity(&self) -> Verbosity {
        self.verbose.clone()
    }

    fn is_recursive(&self) -> bool {
        self.recursive
    }

    fn get_name(&self) -> &str {
        "decrypt"
    }
}

impl Handler for Enc {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        self.process(vault, clipboard)
    }
}

impl Handler for Dec {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        self.process(vault, clipboard)
    }
}
