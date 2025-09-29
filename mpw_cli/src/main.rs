use mpw_core::vault::VaultError;
use std::env;
use std::io::stdin;
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
    let mut user_input = String::new();
    println!("Enter master password:");
    stdin()
        .read_line(&mut user_input)
        .expect("Failed to read user input");
    let master_pw = user_input.trim().into();
    vault.unlock(master_pw)?;
    println!("Enter password name:");
    user_input.clear();
    stdin()
        .read_line(&mut user_input)
        .expect("Failed to read user input");
    let pw_name = user_input.trim();
    let (password, login) = vault.retrieve_password(pw_name)?;
    println!(
        "Password: {}{}",
        password.unsecure(),
        if login.is_some() {
            format!(" (login: {})", login.unwrap().unsecure())
        } else {
            "".into()
        }
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        exit(1);
    }
}
