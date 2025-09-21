use std::env;
use std::fs::File;
use std::path::Path;
use std::io::{stdin, Write};
use secure_string::SecureString;
use ::mpw_rs::cryptography as crypt;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    for argument in &args[1..] {
        println!("{}", argument);
    }

    if args.len() < 3 {
        return Err(String::from("Please specify the path to the vault file and a pw file"));
    }

    let vault_file = &args[1];
    let pw_file = &args[2];
    if !Path::exists(Path::new(vault_file)) {
        return Err(format!("The path {vault_file} does not exist"));
    }

    if !Path::exists(Path::new(pw_file)) {
        return Err(format!("The path {pw_file} does not exist"));
    }

    let pw_file = crypt::EncryptedFile::new(pw_file)?;
    let vault_file = crypt::VaultData::new(vault_file)?;
    println!("{vault_file}");
    println!();
    println!("{pw_file}");
    let mut master_pw = String::new();
    stdin().read_line(& mut master_pw).expect("Error reading user input");
    master_pw = master_pw.trim().to_string();
    let master_pw = SecureString::from(master_pw);
    let master_key = crypt::get_master_key(&master_pw, &vault_file)?;
    let pw = crypt::decrypt_text_file(&pw_file, &master_key)?;

    match String::from_utf8(pw.unsecure().to_vec()) {
        Ok(data) => println!("{}", data),
        Err(msg) => return Err(msg.to_string())
    }

    println!("Enter data to encrypt:");
    let mut input = String::new();
    stdin().read_line(&mut input).map_err(|x| x.to_string())?;
    input = input.trim().to_string();
    let encrypted = crypt::encrypt_text_file(&SecureString::from(input), &master_key)?;
    println!("Specify destination");
    input = String::new();
    stdin().read_line(&mut input).map_err(|x| x.to_string())?;
    input = input.trim().to_string();
    let mut file = File::create(&input).map_err(|msg| format!("Error creating file {}: {msg}", &input))?;
    file.write_all(&encrypted).map_err(|msg| format!("Error writing to file {}: {msg}", &input))?;
    Ok(())
}
