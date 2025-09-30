mod command_processor;
mod vault_processor;

use crate::command_processor::CommandProcessor;
use mpw_core::vault::VaultError;
use rpassword::prompt_password;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::env;
use std::path::Path;
use std::process::exit;
use thiserror;

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

    let mut rl = DefaultEditor::new().expect("Failed to create readline editor");

    let master_pw = prompt_password("Enter master password")
        .expect("Failed to read password")
        .into();
    vault.unlock(master_pw)?;

    let mut vp = vault_processor::VaultProcessor::new(vault);

    loop {
        let prompt = if vp.require_secret() {
            "Password: "
        } else if vp.require_raw() {
            "... "
        } else {
            "> "
        };

        if vp.require_secret() {
            let secret = prompt_password(prompt).expect("Failed to read password").into();
            vp.process_secret(secret);
            continue;
        }

        let readline = rl.readline(prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(&line)
                    .expect("Failed to add history entry");
                let input = line.trim();
                if input == "exit" {
                    break;
                }

                if vp.require_raw() {
                    vp.process_raw(input);
                } else {
                    vp.process_command(input);
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C was pressed
                vp.handle_cancel();
                println!("^C");
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D was pressed
                println!("Exiting...");
                break;
            }
            Err(err) => {
                eprintln!("Error reading input: {}", err);
                break;
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        exit(1);
    }
}
