mod vault_processor;
mod command_processor;

use mpw_core::vault::VaultError;
use std::env;
use std::io::stdin;
use std::path::Path;
use std::process::exit;
use thiserror;
use crate::command_processor::CommandProcessor;

#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("CLI error: {0}")]
    Simple(String),
    #[error(transparent)]
    Core(#[from] VaultError),
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        Self::Simple(value)
    }
}


fn run() -> Result<(), AppError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Please specify the path to a vault");
        exit(1);
    }

    let vault_path = Path::new(&args[1]);
    let mut vault = mpw_core::vault::Vault::load(vault_path.into())?;
    let mut user_input = String::new();
    println!("Enter master password:");
    stdin()
        .read_line(&mut user_input)
        .expect("Failed to read user input");
    let master_pw = user_input.trim().into();
    vault.unlock(master_pw)?;
    let mut vp = vault_processor::VaultProcessor::new(vault);
    user_input.clear();
    loop {
        stdin().read_line(&mut user_input).expect("Failed to read user input");
        user_input = user_input.trim().to_string();
        if user_input == "exit" {
            break;
        }

        if vp.require_raw() {
            vp.process_raw(&user_input);
        } else if vp.require_secret() {
            vp.process_secret(user_input.into());
        } else {
            vp.process_command(&user_input);
        }

        user_input = "".into();
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        exit(1);
    }
}
