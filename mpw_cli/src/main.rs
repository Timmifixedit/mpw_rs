mod command_processor;
mod config;
mod file_name_completer;
mod logo;
mod util;
mod vault_loader;
mod vault_processor;

use crate::command_processor::CommandProcessor;
use crate::vault_loader::VaultLoader;
use mpw_core::vault::VaultError;
use owo_colors::OwoColorize;
use rustyline::error::ReadlineError;
use rustyline::{Context, Editor};
use std::cell::RefCell;
use std::process::exit;
use std::rc::Rc;
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

struct MyHelper {
    pub completer: Rc<RefCell<VaultLoader>>,
}

impl MyHelper {
    pub fn new(completer: Rc<RefCell<VaultLoader>>) -> Self {
        Self { completer }
    }
}

impl rustyline::completion::Completer for MyHelper {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        self.completer.borrow().complete(line, pos, ctx)
    }
}

impl rustyline::highlight::Highlighter for MyHelper {}

impl rustyline::validate::Validator for MyHelper {}

impl rustyline::hint::Hinter for MyHelper {
    type Hint = String;
}
impl rustyline::Helper for MyHelper {}

fn run() -> Result<(), AppError> {
    logo::print_logo();
    let vl = Rc::new(RefCell::new(VaultLoader::new()));
    let helper = MyHelper::new(vl.clone());
    let mut rl = Editor::new().expect("Failed to create readline editor");
    rl.set_helper(Some(helper));

    // Set up Ctrl-C handler
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = interrupted.clone();

    ctrlc::set_handler(move || {
        interrupted_clone.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");
    loop {
        // Reset the interrupted flag at the start of each loop
        interrupted.store(false, Ordering::SeqCst);

        let prompt = if vl.borrow().require_secret() {
            "Password: "
        } else if vl.borrow().require_raw() {
            "... "
        } else {
            "» "
        };

        let readline = if vl.borrow().require_secret() {
            // Use rpassword for secret input (masked)
            print!("{}", prompt.magenta());
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
            rl.readline(&prompt.magenta().to_string())
        };

        match readline {
            Ok(line) => {
                if !vl.borrow().require_secret() {
                    rl.add_history_entry(&line)
                        .expect("Failed to add history entry");
                }
                let input = line.trim();
                if vl.borrow().require_raw() {
                    vl.borrow_mut().process_raw(input);
                } else if vl.borrow().require_secret() {
                    vl.borrow_mut().process_secret(input.into());
                } else {
                    if input == "exit" {
                        vl.borrow_mut().handle_shutdown();
                        break;
                    }

                    if input == "clear" {
                        rl.clear_screen().expect("Failed to clear screen");
                        continue;
                    }

                    vl.borrow_mut().process_command(input);
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C was pressed
                vl.borrow_mut().handle_cancel();
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
