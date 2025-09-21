use std::env;
use std::fs::File;
use std::path::Path;
use std::process::exit;
use std::io::{stdin, Write};
use secure_string::SecureString;
use ::mpw_rs::cryptography as crypt;

fn main() {
    let args: Vec<String> = env::args().collect();
    for argument in &args[1..] {
        println!("{}", argument);
    }

    if args.len() < 3 {
        println!("Please specify the path to the vault file and a pw file");
        exit(1);
    }

    let vault_file = &args[1];
    let pw_file = &args[2];
    if !Path::exists(Path::new(vault_file)) {
        println!("The path {} does not exist", vault_file);
        exit(1);
    }

    if !Path::exists(Path::new(pw_file)) {
        println!("The path {} does not exist", pw_file);
        exit(1);
    }

    let pw_file = match crypt::EncryptedFile::new(pw_file) {
        Ok(file) => file,
        Err(msg) => {
            println!("Error parsing file header: {msg}");
            exit(1);
        }
    };

    let vault_file = match crypt::VaultData::new(vault_file) {
        Ok(file) => file,
        Err(msg) => {
            println!("Error parsing vault file: {msg}");
            exit(1);
        }
    };

    println!("{vault_file}");
    println!();
    println!("{pw_file}");
    let mut master_pw = String::new();
    stdin().read_line(& mut master_pw).expect("Error reading user input");
    master_pw = master_pw.trim().to_string();
    let master_pw = SecureString::from(master_pw);
    let master_key = match crypt::get_master_key(&master_pw, &vault_file) {
        Ok(key) => key,
        Err(msg) => {
            println!("{msg}");
            exit(1);
        }
    };
    let pw = match crypt::decrypt_text_file(&pw_file, &master_key) {
        Ok(pw) => pw,
        Err(msg) => {
            println!("{msg}");
            exit(1);
        }
    };

    match String::from_utf8(pw.unsecure().to_vec()) {
        Ok(data) => println!("{}", data),
        Err(msg) => {
            println!("{msg}");
            exit(1);
        }
    }

    println!("Enter data to encrypt:");
    let mut input = String::new();
    stdin().read_line(&mut input).expect("Error reading user input");
    input = input.trim().to_string();
    let encrypted = crypt::encrypt_text_file(&SecureString::from(input), &master_key).expect("Error encrypting data");
    println!("Specify destination");
    input = String::new();
    stdin().read_line(&mut input).expect("Error reading user input");
    input = input.trim().to_string();
    let mut file = File::create(&input).expect(format!("Error creating file {}", &input).as_str());
    file.write_all(&encrypted).expect(format!("Error writing to file {}", &input).as_str());
}
