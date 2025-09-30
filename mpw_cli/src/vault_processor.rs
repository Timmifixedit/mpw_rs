use crate::command_processor as cp;
use arboard;
use arboard::Clipboard;
use clap::{Args, Parser, Subcommand};
use mpw_core::vault;
use mpw_core::vault::{Vault, VaultError};
use secure_string::SecureString;
use std::num::NonZeroU32;

type RawHandler = Box<dyn FnOnce(&mut Vault, String) -> (VaultState, Followup)>;
type SecretHandler = Box<dyn FnOnce(&mut Vault, SecureString) -> (VaultState, Followup)>;

enum Followup {
    Raw(RawHandler),
    Secret(SecretHandler),
    None,
}

#[cfg(windows)]
const ENDL: &str = "\r\n";
#[cfg(not(windows))]
const ENDL: &str = "\n";

#[derive(Debug, Args)]
#[command(about = "retrieve a password", long_about = None)]
pub struct Get {
    #[arg(required = true)]
    pub name: String,

    #[arg(short, long, default_value = "false")]
    pub show: bool,
}

#[derive(Debug, Args)]
#[command(about = "add a password", long_about = None)]
pub struct Add {
    #[arg(required = true)]
    pub name: String,

    #[arg(short, long, default_value = None)]
    pub rand_len: Option<NonZeroU32>,

    #[arg(short, long, default_value = None)]
    pub invalid_chars: Option<String>,

    #[arg(short, long, default_value = "false")]
    pub overwrite: bool,

    #[arg(short, long, default_value = None)]
    pub login: Option<String>,
}

#[derive(Debug, Args)]
#[command(about = "list all passwords / files", long_about = None)]
pub struct List {
    #[arg(required = false, default_value = None)]
    pub search: Option<String>,

    #[arg(short, long, default_value = "false")]
    pub path: bool,

    #[arg(short, long, default_value = "false")]
    pub files: bool,
}

#[derive(Debug, Args)]
#[command(about = "remove passwords / files", long_about = None)]
pub struct Remove {
    #[arg(required = true)]
    pub names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    pub files: bool,

    #[arg(short, long, default_value = "false")]
    pub yes: bool,
}

#[derive(Debug, Args)]
#[command(about = "change master password", long_about = None)]
pub struct ChangePw {}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
enum Verbosity {
    Quiet,
    Normal,
    All,
}

#[derive(Debug, Args)]
#[command(about = "encrypt file system entries", long_about = None)]
pub struct Enc {
    #[arg(required = true)]
    names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    path: bool,

    #[arg(short, long, default_value = "quiet")]
    verbose: Verbosity,
}

#[derive(Debug, Args)]
#[command(about = "decrypt file system entries", long_about = None)]
pub struct Dec {
    #[arg(required = true)]
    names: Vec<String>,

    #[arg(short, long, default_value = "false")]
    path: bool,

    #[arg(short, long, default_value = "quiet")]
    verbose: Verbosity,
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    #[command(name = "get")]
    Get(Get),
    #[command(name = "add")]
    Add(Add),
    #[command(name = "ls")]
    List(List),
    #[command(name = "rm")]
    Remove(Remove),
    #[command(name = "chpw")]
    ChangePw(ChangePw),
    #[command(name = "enc")]
    Enc(Enc),
    #[command(name = "dec")]
    Dec(Dec),
}

#[derive(Debug, Parser)]
#[command(no_binary_name = true)]
struct VaultCli {
    #[command(subcommand)]
    cmd: VaultCommand,
}

trait Handler {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup);
}

impl Handler for VaultCommand {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        match self {
            VaultCommand::Get(args) => args.handle(vault, clipboard),
            VaultCommand::Add(args) => args.handle(vault, clipboard),
            VaultCommand::List(args) => args.handle(vault, clipboard),
            VaultCommand::Remove(args) => args.handle(vault, clipboard),
            VaultCommand::ChangePw(args) => args.handle(vault, clipboard),
            VaultCommand::Enc(args) => args.handle(vault, clipboard),
            VaultCommand::Dec(args) => args.handle(vault, clipboard),
        }
    }
}

impl Handler for VaultCli {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        self.cmd.handle(vault, clipboard)
    }
}

impl Handler for Get {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        vault.retrieve_password(&self.name).map_or_else(
            |e| println!("{}", e.to_string()),
            |(pw, login)| {
                if let Some(login) = login {
                    println!("{}", login);
                }
                if self.show {
                    println!("{}", pw.unsecure());
                } else {
                    if let Err(e) = clipboard.set_text(pw.unsecure()) {
                        eprintln!("Error copying password to clipboard: {}", e.to_string());
                    } else {
                        println!("Password copied to clipboard");
                    }
                }
            },
        );

        (VaultState::Unlocked, Followup::None)
    }
}

impl Handler for Add {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let result = (|| {
            let exists = vault.list_passwords(None)?.contains(&self.name);
            if exists && !self.overwrite {
                return Err(VaultError::AlreadyExists(self.name.clone()));
            }

            if self.overwrite && !exists {
                return Err(VaultError::PasswordNotFound(self.name.clone()));
            }

            let success_msg = format!(
                "Successfully {} password {}",
                if self.overwrite { "updated" } else { "created" },
                self.name
            );

            if let Some(r_len) = self.rand_len {
                let pw = vault::random_password(r_len, self.invalid_chars.as_deref())?;
                vault.write_password(&self.name, pw, self.login.as_deref(), self.overwrite)?;
                println!("{}", success_msg);
                return Ok((VaultState::Unlocked, Followup::None));
            }

            println!("Enter password:");
            let followup = Followup::Secret(Box::new(move |vlt, pw| {
                println!(
                    "{}",
                    vlt.write_password(
                        self.name.as_str(),
                        pw,
                        self.login.as_deref(),
                        self.overwrite,
                    )
                    .map_or_else(|e| e.to_string(), |_| success_msg)
                );
                (VaultState::Unlocked, Followup::None)
            }));

            Ok((VaultState::EnterPw, followup))
        })();
        result.unwrap_or_else(|e| {
            println!("{}", e.to_string());
            (VaultState::Unlocked, Followup::None)
        })
    }
}

impl Handler for List {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let entries;
        if self.files {
            entries = vault.list_files(self.path, self.search.as_deref());
        } else {
            entries = vault
                .list_passwords(self.search.as_deref())
                .unwrap_or_else(|e| {
                    println!("{}", e.to_string());
                    vec![]
                })
        }

        for entry in entries {
            println!("{}", entry);
        }
        (VaultState::Unlocked, Followup::None)
    }
}

impl Handler for Enc {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        if self.path {
            for name in &self.names {
                if let Err(err) = vault.encrypt_file(std::path::Path::new(name)) {
                    match &self.verbose {
                        Verbosity::Quiet => {}
                        Verbosity::Normal => {
                            println!("Failed to encrypt file {}", name);
                        }
                        Verbosity::All => {
                            println!("Failed to encrypt file {}: {}", name, err.to_string());
                        }
                    }
                }
            }

            return (VaultState::Unlocked, Followup::None);
        }

        todo!()
    }
}

impl Handler for Dec {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        if self.path {
            for name in &self.names {
                if let Err(err) = vault.decrypt_file(std::path::Path::new(name)) {
                    match &self.verbose {
                        Verbosity::Quiet => {}
                        Verbosity::Normal => {
                            println!("Failed to decrypt file {}", name);
                        },
                        Verbosity::All => {
                            println!("Failed to decrypt file {}: {}", name, err.to_string());
                        }
                    }
                }
            }

            return (VaultState::Unlocked, Followup::None);
        }

        todo!()
    }
}

impl Handler for ChangePw {
    fn handle(self, _: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        println!("Enter you new master password:");
        let followup = Followup::Secret(Box::new(move |_, pw1| {
            println!("Enter your new master password again:");
            (
                VaultState::EnterPw,
                Followup::Secret(Box::new(move |vlt, pw2| {
                    if pw1 != pw2 {
                        println!("Passwords do not match");
                        return (VaultState::Unlocked, Followup::None);
                    }

                    vlt.change_master_password(pw1).map_or_else(
                        |e| println!("Failed to change master password: {}", e.to_string()),
                        |_| println!("Successfully changed master password"),
                    );
                    (VaultState::Unlocked, Followup::None)
                })),
            )
        }));
        (VaultState::EnterPw, followup)
    }
}

impl Handler for Remove {
    fn handle(self, vault: &mut Vault, _: &mut Clipboard) -> (VaultState, Followup) {
        let remove = move |vlt: &mut Vault| {
            for name in self.names {
                if self.files {
                    todo!()
                } else {
                    vlt.delete_password(&name).map_or_else(
                        |e| println!("failed to delete password {}: {}", name, e.to_string()),
                        |_| println!("Successfully deleted password {}", name),
                    );
                }
            }
        };

        if !self.yes && !self.files {
            println!("Please confirm the deletion of the passwords (type 'yes' to confirm)");
            (
                VaultState::RawInput,
                Followup::Raw(Box::new(move |vlt, cmd| {
                    if cmd != "yes" {
                        println!("Aborted. Type 'yes' to confirm removal");
                        return (VaultState::Unlocked, Followup::None);
                    }

                    remove(vlt);
                    (VaultState::Unlocked, Followup::None)
                })),
            )
        } else {
            remove(vault);
            (VaultState::Unlocked, Followup::None)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum VaultState {
    Locked,
    Unlocked,
    EnterPw,
    RawInput,
}

pub struct VaultProcessor {
    vault: Vault,
    state: VaultState,
    process_raw: Option<RawHandler>,
    process_secret: Option<SecretHandler>,
    clipboard: Clipboard,
}

impl VaultProcessor {
    pub fn new(vault: Vault) -> VaultProcessor {
        let state = if vault.is_locked() {
            VaultState::Locked
        } else {
            VaultState::Unlocked
        };
        VaultProcessor {
            vault,
            state,
            process_raw: None,
            process_secret: None,
            clipboard: Clipboard::new().expect("Failed to initialize clipboard"),
        }
    }

    fn set_followup(&mut self, followup: Followup) {
        match followup {
            Followup::Raw(r) => {
                self.process_raw = Some(r);
            }
            Followup::Secret(s) => {
                self.process_secret = Some(s);
            }
            _ => {}
        }
    }
}

impl cp::CommandProcessor for VaultProcessor {
    fn process_command(&mut self, command: &str) {
        if self.state != VaultState::Unlocked {
            panic!("Invalid state {:?}", self.state);
        }

        let args = command.trim().split_whitespace();
        let parsed = match VaultCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(e) => {
                return println!("Error parsing command: {}", e);
            }
        };

        let (state, followup) = parsed.handle(&mut self.vault, &mut self.clipboard);
        self.state = state;
        self.set_followup(followup);
    }

    fn process_raw(&mut self, command: &str) {
        if self.state != VaultState::RawInput {
            panic!("Invalid state {:?}", self.state);
        }

        let handler = self.process_raw.take().expect("No raw handler set");
        let (state, followup) = handler(&mut self.vault, command.to_string());
        self.state = state;
        self.set_followup(followup);
    }

    fn process_secret(&mut self, secret: SecureString) {
        if self.state != VaultState::EnterPw && self.state != VaultState::Locked {
            panic!("Invalid state {:?}", self.state);
        }

        let handler = self.process_secret.take().expect("No secret handler set");
        let (state, followup) = handler(&mut self.vault, secret);
        self.state = state;
        self.set_followup(followup);
    }

    fn require_secret(&self) -> bool {
        self.state == VaultState::EnterPw || self.state == VaultState::Locked
    }

    fn require_raw(&self) -> bool {
        self.state == VaultState::RawInput
    }

    fn handle_cancel(&mut self) {
        if self.state == VaultState::EnterPw || self.state == VaultState::RawInput {
            self.state = VaultState::Unlocked;
            self.process_raw = None;
            self.process_secret = None;
        }
    }

    fn help(&self) {
        todo!()
    }
}
