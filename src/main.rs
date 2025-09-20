use std::env;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::process::exit;

struct RawFile {
    path: String,
    cypher_data: Vec<u8>,
}

struct VaultData {
    iv: Vec<u8>,
    cypher_master_key: Vec<u8>,
    salt: Vec<u8>
}

struct EncryptedFile {
    master_iv: Vec<u8>,
    iv: Vec<u8>,
    cypher_key: Vec<u8>,
    cypher_data: Vec<u8>
}

impl Display for EncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "Header:\n\
            \tMaster IV: {:02X?} (len {})\n\
            \tIV: {:02X?} (len {})\n\
            \tKey {:02X?} (len {})\n\
            Data: {:02X?} (len {})",
            self.master_iv, self.iv.len(), self.iv, self.iv.len(), self.cypher_key,
            self.cypher_key.len(), self.cypher_data, self.cypher_data.len()
        );
        write!(f, "{}", str)
    }
}

impl Display for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "IV: {:02X?} (len {})\n\
             Key {:02X?} (len {})\n\
             Salt {:02X?} (len {})",
            self.iv, self.iv.len(), self.cypher_master_key, self.cypher_master_key.len(),
            self.salt, self.salt.len());
        write!(f, "{}", str)
    }
}

impl VaultData {
    fn new(raw_data: &Vec<u8>) -> Result<VaultData, String> {
        if raw_data.len() < 8 {
            return Err(String::from("expected at least 8 bytes of header data"));
        }

        let iv_length = u32::from_ne_bytes(raw_data[0..4].try_into().unwrap()) as usize;
        let key_length = u32::from_ne_bytes(raw_data[4..8].try_into().unwrap()) as usize;
        if raw_data.len() < 8 + iv_length + key_length {
            return Err(format!(
                "Expected {} bytes of IV and {} bytes of key data but only got {} bytes of data",
                iv_length,
                key_length,
                raw_data.len()
            ));
        }

        let iv = raw_data[8..8 + iv_length].to_vec();
        let cypher_key = raw_data[8 + iv_length..8 + iv_length + key_length].to_vec();
        if raw_data.len() < 12 + iv_length + key_length + 4 {
            return Err(String::from("expected at least 4 additional bytes of salt length"));
        }

        let salt_length = u32::from_ne_bytes(
            raw_data[8 + iv_length + key_length..8 + iv_length + key_length + 4]
                .try_into().unwrap()) as usize;
        if raw_data.len() < 12 + iv_length + key_length + salt_length {
            return Err(format!("Expected {} bytes of salt but only got {} bytes left",
                               salt_length, raw_data.len() - 12 - iv_length - key_length));
        }

        let salt = raw_data[12 + iv_length + key_length..12 + iv_length + key_length + salt_length]
            .to_vec();
        Ok(VaultData {
            iv,
            cypher_master_key: cypher_key,
            salt
        })
    }
}

impl EncryptedFile {
    fn new(raw_data: &Vec<u8>) -> Result<EncryptedFile, String> {
        if raw_data.len() < 12 {
            return Err(String::from("Expected 12 bytes of header"));
        }

        let master_iv_len = u32::from_ne_bytes(raw_data[0..4].try_into().unwrap()) as usize;
        let iv_len = u32::from_ne_bytes(raw_data[4..8].try_into().unwrap()) as usize;
        let key_len = u32::from_ne_bytes(raw_data[8..12].try_into().unwrap()) as usize;
        if raw_data.len() < 12 + master_iv_len + iv_len + key_len {
            return Err(format!(
                "Expected {} bytes of master IV, {} bytes of IV and {} bytes of key data but only \
                got {} bytes of data", master_iv_len, iv_len, key_len, raw_data.len()));
        }

        let master_iv = raw_data[12..12 + master_iv_len].to_vec();
        let iv = raw_data[12 + master_iv_len..12 + master_iv_len + iv_len].to_vec();
        let cypher_key =
            raw_data[12 + master_iv_len + iv_len..12 + master_iv_len + iv_len + key_len].to_vec();
        let data = raw_data[master_iv_len + iv_len + key_len..].to_vec();
        Ok(EncryptedFile { master_iv, iv, cypher_key, cypher_data: data })
    }
}

impl RawFile {
    fn new(path: String) -> Result<RawFile, String> {
        if !Path::new(&path).exists() {
            return Err(String::from("Path does not exist"));
        }

        let raw_data = fs::read(&path);
        match raw_data {
            Ok(data) => Ok(RawFile {
                path,
                cypher_data: data,
            }),
            Err(msg) => Err(format!("Error reading file: {}", msg.to_string())),
        }
    }
}

fn parse_and_display<T: Display>(file_path: String, new: fn(&Vec<u8>) -> Result<T, String>) {
    let file = match RawFile::new(file_path) {
        Ok(file) => file,
        Err(msg) => {
            println!("{}", msg);
            exit(1);
        }
    };

    let header = match new(&file.cypher_data) {
        Ok(header) => header,
        Err(msg) => {
            println!("{}", msg);
            exit(1);
        }
    };

    println!("{}", header);
}

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

    parse_and_display(vault_file.clone(), VaultData::new);
    println!();
    parse_and_display(pw_file.clone(), EncryptedFile::new);
}
