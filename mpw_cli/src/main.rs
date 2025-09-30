mod vault_processor;
mod command_processor;

use mpw_core::vault::VaultError;
use std::env;
use std::path::Path;
use std::process::exit;
use thiserror;
use crate::command_processor::CommandProcessor;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

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
    
    println!("Enter master password:");
    let master_pw = rl.readline("").expect("Failed to read master password");
    vault.unlock(master_pw.trim().into())?;
    
    let mut vp = vault_processor::VaultProcessor::new(vault);
    
    loop {
        let prompt = if vp.require_secret() {
            "Password: "
        } else if vp.require_raw() {
            "... "
        } else {
            "> "
        };
        
        let readline = rl.readline(prompt);
        match readline {
            Ok(line) => {
                rl.add_history_entry(&line).expect("Failed to add history entry");
                let input = line.trim();
                if input == "exit" {
                    break;
                }

                if vp.require_raw() {
                    vp.process_raw(input);
                } else if vp.require_secret() {
                    vp.process_secret(input.into());
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
