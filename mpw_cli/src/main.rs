use crypt::AesKey;
use mpw_core::cryptography as crypt;
use mpw_core::error::MpwError;
use openssl::symm::{Cipher, decrypt};
use secure_string::SecureString;
use std::env;
use std::fs::File;
use std::io::SeekFrom::Start;
use std::io::{Seek, Write, stdin};
use std::path::Path;
use thiserror;

#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("CLI error: {0}")]
    Simple(String),
    #[error(transparent)]
    Core(#[from] MpwError),
}

impl From<String> for AppError {
    fn from(value: String) -> Self {
        Self::Simple(value)
    }
}

fn run() -> Result<(), AppError> {
    let args: Vec<String> = env::args().collect();
    for argument in &args[1..] {
        println!("{}", argument);
    }

    if args.len() < 3 {
        return Err(String::from("Please specify the path to the vault file and a pw file").into());
    }

    let vault_file = Path::new(&args[1]);
    let pw_file = Path::new(&args[2]);
    if !Path::exists(Path::new(vault_file)) {
        return Err(format!("The path {} does not exist", vault_file.to_string_lossy()).into());
    }

    if !Path::exists(Path::new(pw_file)) {
        return Err(format!("The path {} does not exist", pw_file.to_string_lossy()).into());
    }

    let f = File::open(pw_file).map_err(|e| AppError::Simple(e.to_string()))?;
    let pw_header = crypt::FileHeader::new(f)?;
    let f = File::open(vault_file).map_err(|e| AppError::Simple(e.to_string()))?;
    let vault_file = crypt::VaultData::new(f)?;
    println!("{vault_file}");
    println!();
    println!("{pw_header}");
    let mut master_pw = String::new();
    stdin()
        .read_line(&mut master_pw)
        .expect("Error reading user input");
    master_pw = master_pw.trim().to_string();
    let master_pw = SecureString::from(master_pw);
    let master_key = crypt::get_master_key(master_pw, &vault_file)?;
    let pw = crypt::decrypt_text_from_file(&pw_file, &master_key)?;
    println!("{}", pw.unsecure());

    println!("Enter data to encrypt:");
    let mut input = String::new();
    stdin().read_line(&mut input).map_err(|x| x.to_string())?;
    let src_file = input.trim().to_string();
    println!("Specify destination");
    input = String::new();
    stdin().read_line(&mut input).map_err(|x| x.to_string())?;
    input = input.trim().to_string();
    let src_file_handle = File::options()
        .read(true)
        .write(true)
        .open(&src_file)
        .map_err(|msg| format!("Error opening file {}: {msg}", &src_file))?;
    let dest_file = Path::new(&input);
    let mut file =
        File::create(&input).map_err(|msg| format!("Error creating file {}: {msg}", &input))?;
    let (header, key, iv) = crypt::generate_file_header(&master_key)?;
    let raw: Vec<u8> = header.into();
    file.write_all(&raw)
        .map_err(|msg| format!("Error writing header to file {}: {msg}", &input))?;
    crypt::crypto_write(src_file_handle, &mut file, &key, &iv)?;
    std::fs::remove_file(&src_file)
        .map_err(|msg| format!("Error removing file {}: {msg}", &src_file))?;

    println!("File encrypted successfully. Press enter when you're ready to decrypt");
    stdin()
        .read_line(&mut String::new())
        .map_err(|x| x.to_string())?;
    let f = File::open(dest_file).map_err(|e| AppError::Simple(e.to_string()))?;
    let enc_file = crypt::FileHeader::new(f)?;
    let key = match decrypt(
        Cipher::aes_256_cbc(),
        master_key.unsecure(),
        Some(&enc_file.master_iv),
        &enc_file.cipher_key,
    ) {
        Ok(key) => AesKey::from(key.as_chunks::<32>().0[0]),
        Err(msg) => return Err(MpwError::Cryptography(msg.into()).into()),
    };
    let mut src_file_handle = File::open(dest_file)
        .map_err(|msg| format!("Error opening file {}: {msg}", dest_file.to_string_lossy()))?;
    src_file_handle
        .seek(Start(enc_file.data_offset() as u64))
        .map_err(|msg| {
            format!(
                "Error seeking to data offset {}: {msg}",
                enc_file.data_offset()
            )
        })?;
    let mut file = File::create(&src_file)
        .map_err(|msg| format!("Error creating file {}: {msg}", &src_file))?;
    crypt::crypto_read(&src_file_handle, &mut file, &key, &enc_file.iv)?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
