use std::num::NonZeroU32;
use crate::command_processor as cp;
use arboard;
use clap::{Args, Parser, Subcommand};
use mpw_core::vault;
use mpw_core::vault::{Vault, VaultError};
use secure_string::SecureString;

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
    process_raw: Option<Box<dyn FnOnce(&mut Vault, String) -> (String, VaultState)>>,
    process_secret: Option<Box<dyn FnOnce(&mut Vault, SecureString) -> (String, VaultState)>>,
    clipboard: arboard::Clipboard,
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
            clipboard: arboard::Clipboard::new().expect("Failed to initialize clipboard"),
        }
    }

    fn get(&mut self, args: Get) -> String {
        self.vault
            .retrieve_password(&args.name)
            .map(|(pw, login)| {
                let mut ret = login.unwrap_or_else(|| "".into()).to_string() + ENDL;
                if args.show {
                    ret += pw.unsecure().into();
                } else {
                    if let Err(e) = self.clipboard.set_text(pw.unsecure()) {
                        ret += &format!("Error copying password to clipboard: {}", e.to_string());
                    } else {
                        ret += "Password copied to clipboard".into();
                    }
                }

                ret
            })
            .unwrap_or_else(|e| e.to_string())
    }

    fn add(&mut self, args: Add) -> String {
        let result: Result<String, VaultError> = (|| {
            let exists = self.vault.list_passwords()?.contains(&args.name);
            if exists && !args.overwrite {
                return Err(VaultError::AlreadyExists(args.name.clone()));
            }

            if args.overwrite && !exists {
                return Err(VaultError::PasswordNotFound(args.name.clone()));
            }

            let success_msg = format!(
                "Successfully {} password {}",
                if args.overwrite { "updated" } else { "created" },
                args.name
            );

            if let Some(r_len) = args.rand_len {
                let pw = vault::random_password(r_len, args.invalid_chars.as_deref())?;
                self.vault
                    .write_password(&args.name, pw, args.login.as_deref(), args.overwrite)?;
                return Ok(success_msg);
            }

            self.process_secret = Some(Box::new(move |vlt, pw| {
                (
                    vlt.write_password(
                        args.name.as_str(),
                        pw,
                        args.login.as_deref(),
                        args.overwrite,
                    )
                    .map_or_else(|e| e.to_string(), |_| success_msg),
                    VaultState::Unlocked,
                )
            }));
            self.state = VaultState::EnterPw;
            Ok("Enter your password".into())
        })();

        result.unwrap_or_else(move |e| e.to_string())
    }
}

impl cp::CommandProcessor for VaultProcessor {
    fn process_command(&mut self, command: &str) -> String {
        if self.state != VaultState::Unlocked {
            panic!("Invalid state {:?}", self.state);
        }

        let args = command.trim().split_whitespace();
        let parsed = match VaultCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(e) => {
                return format!("Error parsing command: {}", e);
            }
        };

        match parsed.cmd {
            VaultCommand::Get(args) => self.get(args),
            VaultCommand::Add(args) => self.add(args),
        }
    }

    fn process_raw(&mut self, command: &str) -> String {
        if self.state != VaultState::Unlocked {
            panic!("Invalid state {:?}", self.state);
        }

        todo!()
    }

    fn process_secret(&mut self, secret: SecureString) -> String {
        if self.state != VaultState::EnterPw && self.state != VaultState::Locked {
            panic!("Invalid state {:?}", self.state);
        }

        let handler = self.process_secret.take().expect("No secret handler set");
        let (msg, state) = handler(&mut self.vault, secret);
        self.state = state;
        msg
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

    fn help(&self) -> String {
        todo!()
    }
}
