mod add;
mod handler;
mod list;
mod remove;
mod load;

use std::fmt::{Display, Formatter};
use crate::command_processor::CommandProcessor;
use add::Add;
use clap::{Parser, Subcommand};
use handler::{Followup, Handler, SecretHandler};
use list::List;
use mpw_core::path_manager::PathManager;
use remove::Remove;
use secure_string::SecureString;
use load::Load;
use crate::vault_processor::VaultProcessor;

const APP_NAME: &str = "mpw";
const CONFIG_NAME: &str = "config.vlt";

pub enum LoaderState {
    Select,
    Loaded(VaultProcessor),
    Secret,
}

impl Display for LoaderState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LoaderState::Select => write!(f, "Select"),
            LoaderState::Loaded(_) => write!(f, "Loaded"),
            LoaderState::Secret => write!(f, "Secret"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum LoaderCommand {
    #[command(name = "add")]
    Add(Add),
    #[command(name = "rm")]
    Remove(Remove),
    #[command(name = "ls")]
    List(List),
    #[command(name = "load")]
    Load(Load),
}

#[derive(Debug, Parser)]
#[command(no_binary_name = true)]
struct LoaderCli {
    #[command(subcommand)]
    cmd: LoaderCommand,
}

impl Handler for LoaderCommand {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        match self {
            LoaderCommand::Add(args) => args.handle(entries),
            LoaderCommand::Remove(args) => args.handle(entries),
            LoaderCommand::List(args) => args.handle(entries),
            LoaderCommand::Load(args) => args.handle(entries),
        }
    }
}

impl Handler for LoaderCli {
    fn handle(self, entries: &mut PathManager) -> (LoaderState, Followup) {
        self.cmd.handle(entries)
    }
}

pub struct VaultLoader {
    entries: PathManager,
    process_secret: Option<SecretHandler>,
    state: LoaderState,
}

impl VaultLoader {
    pub fn set_followup(&mut self, followup: Followup) {
        match followup {
            Followup::Secret(s) => {
                self.process_secret = Some(s);
            }
            Followup::None => {}
        }
    }
}

impl VaultLoader {
    pub fn new() -> VaultLoader {
        let entries = confy::load(APP_NAME, Some(CONFIG_NAME)).unwrap_or_else(|err| {
            eprintln!("Error loading config: {}", err);
            PathManager::default()
        });

        VaultLoader {
            entries,
            process_secret: None,
            state: LoaderState::Select,
        }
    }
}

impl CommandProcessor for VaultLoader {
    fn process_command(&mut self, command: &str) {
        if let LoaderState::Secret = self.state {
            panic!("Invalid state {}", self.state);
        }

        if let LoaderState::Loaded(vp) = &mut self.state {
            vp.process_command(command);
            return;
        }

        let args = command.trim().split_whitespace();
        let parsed = match LoaderCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(e) => {
                return println!("Error parsing command: {}", e);
            }
        };

        let (state, followup) = parsed.handle(&mut self.entries);
        self.state = state;
        self.set_followup(followup);
    }

    fn process_raw(&mut self, command: &str) {
        if let LoaderState::Loaded(vp) = &mut self.state {
            vp.process_raw(command);
            return;
        }

        panic!("Invalid state {}", self.state);
    }

    fn process_secret(&mut self, secret: SecureString) {
        if let LoaderState::Loaded(vp) = &mut self.state {
            vp.process_secret(secret);
            return;
        }

        if let LoaderState::Secret = self.state {
            let handler = self.process_secret.take().expect("No secret handler set");
            let (state, followup) = handler(secret);
            self.state = state;
            self.set_followup(followup);
        } else {
            panic!("Invalid state {}", self.state);
        }
    }

    fn require_secret(&self) -> bool {
        match &self.state {
            LoaderState::Select => false,
            LoaderState::Loaded(vp) => vp.require_secret(),
            LoaderState::Secret => true,
        }
    }

    fn require_raw(&self) -> bool {
        match &self.state {
            LoaderState::Loaded(vp) => vp.require_raw(),
            _ => false,
        }
    }

    fn handle_cancel(&mut self) {
        if let LoaderState::Loaded(vp) = &mut self.state {
            vp.handle_cancel();
            if vp.is_locked() {
                self.state = LoaderState::Select;
                self.process_secret = None;
            }
        }
    }
}
