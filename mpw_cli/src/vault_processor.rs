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

#[derive(Debug, Subcommand)]
enum VaultCommand {
    #[command(name = "get")]
    Get(Get),
    #[command(name = "add")]
    Add(Add),
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
            let exists = vault.list_passwords()?.contains(&self.name);
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
            Followup::Raw(r) => {self.process_raw = Some(r);}
            Followup::Secret(s) => {self.process_secret = Some(s);}
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

        let (state, followup) = match parsed.cmd {
            VaultCommand::Get(args) => args.handle(&mut self.vault, &mut self.clipboard),
            VaultCommand::Add(args) => args.handle(&mut self.vault, &mut self.clipboard)
        };
        self.state = state;
        self.set_followup(followup);
    }

    fn process_raw(&mut self, command: &str) {
        if self.state != VaultState::Unlocked {
            panic!("Invalid state {:?}", self.state);
        }

        todo!()
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
        todo!()
    }

    fn help(&self) {
        todo!()
    }
}
