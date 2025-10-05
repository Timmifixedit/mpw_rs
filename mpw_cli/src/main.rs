mod command_processor;
mod vault_processor;
mod vault_loader;
mod config;
mod util;

use crate::command_processor::CommandProcessor;
use crate::vault_loader::VaultLoader;
use mpw_core::vault::VaultError;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
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
    let mut rl = DefaultEditor::new().expect("Failed to create readline editor");

    // Set up Ctrl-C handler
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = interrupted.clone();

    ctrlc::set_handler(move || {
        interrupted_clone.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut vl = VaultLoader::new();
    loop {

        // Reset the interrupted flag at the start of each loop
        interrupted.store(false, Ordering::SeqCst);

        let prompt = if vl.require_secret() {
            "Password: "
        } else if vl.require_raw() {
            "... "
        } else {
            "> "
        };

        let readline = if vl.require_secret() {
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
                if !vl.require_secret() {
                    rl.add_history_entry(&line)
                        .expect("Failed to add history entry");
                }
                let input = line.trim();
                if input == "exit" {
                    break;
                }

                if vl.require_raw() {
                    vl.process_raw(input);
                } else if vl.require_secret() {
                    vl.process_secret(input.into());
                } else {
                    if input == "clear" {
                        rl.clear_screen().expect("Failed to clear screen");
                        continue;
                    }

                    vl.process_command(input);
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C was pressed
                vl.handle_cancel();
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
