mod add;
mod chpw;
mod enc_dec;
mod get;
mod handler;
mod list;
mod lock;
mod mv;
mod remove;
mod secure_release;

use crate::command_processor as cp;
use add::Add;
use arboard;
use arboard::Clipboard;
use chpw::ChangePw;
use clap::{Parser, Subcommand};
use enc_dec::{Dec, Enc};
use get::Get;
use handler::{Followup, Handler, RawHandler, SecretHandler};
use list::List;
use lock::Lock;
use mpw_core::vault::Vault;
use mv::Move;
use remove::Remove;
use secure_release::{Release, Secure};
use secure_string::SecureString;

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
    #[command(name = "sec")]
    Sec(Secure),
    #[command(name = "rel")]
    Release(Release),
    #[command(name = "mv")]
    Move(Move),
    #[command(name = "lock")]
    Lock(Lock),
}

#[derive(Debug, Parser)]
#[command(no_binary_name = true)]
struct VaultCli {
    #[command(subcommand)]
    cmd: VaultCommand,
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
            VaultCommand::Sec(args) => args.handle(vault, clipboard),
            VaultCommand::Release(args) => args.handle(vault, clipboard),
            VaultCommand::Move(args) => args.handle(vault, clipboard),
            VaultCommand::Lock(args) => args.handle(vault, clipboard),
        }
    }
}

impl Handler for VaultCli {
    fn handle(self, vault: &mut Vault, clipboard: &mut Clipboard) -> (VaultState, Followup) {
        self.cmd.handle(vault, clipboard)
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
        let state;
        let secret_handler: Option<SecretHandler>;
        if vault.is_locked() {
            state = VaultState::Locked;
            secret_handler = Some(Box::new(|vault, pw| lock::unlock(vault, pw)));
        } else {
            state = VaultState::Unlocked;
            secret_handler = None;
        };
        VaultProcessor {
            vault,
            state,
            process_raw: None,
            process_secret: secret_handler,
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

    pub fn is_locked(&self) -> bool {
        self.state == VaultState::Locked
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
}
