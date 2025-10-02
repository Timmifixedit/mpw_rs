mod command_processor;
mod vault_processor;

use crate::command_processor::CommandProcessor;
use mpw_core::vault::VaultError;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::env;
use std::path::Path;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

    // Set up Ctrl-C handler
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = interrupted.clone();

    ctrlc::set_handler(move || {
        interrupted_clone.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Enter master password:");
    let master_pw = rpassword::read_password().expect("Failed to read master password");

    if interrupted.load(Ordering::SeqCst) {
        println!("^C");
        return Ok(());
    }

    vault.unlock(master_pw.trim().into())?;

    let mut vp = vault_processor::VaultProcessor::new(vault);

    loop {
        // Reset the interrupted flag at the start of each loop
        interrupted.store(false, Ordering::SeqCst);

        let prompt = if vp.require_secret() {
            "Password: "
        } else if vp.require_raw() {
            "... "
        } else {
            "> "
        };

        let readline = if vp.require_secret() {
            // Use rpassword for secret input (masked)
            print!("{}", prompt);
            use std::io::Write;
            std::io::stdout().flush().expect("Failed to flush stdout");

            let result = rpassword::read_password().map_err(|e| ReadlineError::Io(e));

            // Check if Ctrl-C was pressed during password input
            if interrupted.load(Ordering::SeqCst) {
                Err(ReadlineError::Interrupted)
            } else {
                result
            }
        } else {
            // Use rustyline for regular input
            rl.readline(prompt)
        };

        match readline {
            Ok(line) => {
                if !vp.require_secret() {
                    rl.add_history_entry(&line)
                        .expect("Failed to add history entry");
                }
                let input = line.trim();
                if input == "exit" {
                    break;
                }

                if vp.require_raw() {
                    vp.process_raw(input);
                } else if vp.require_secret() {
                    vp.process_secret(input.into());
                } else {
                    if input == "clear" {
                        rl.clear_screen().expect("Failed to clear screen");
                        continue;
                    }

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
