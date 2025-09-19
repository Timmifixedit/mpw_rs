use std::env;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::process::exit;

struct EncryptedFile {
    path: String,
    cypher_data: Vec<u8>,
}

struct PwHeader {
    master_iv: Vec<u8>,
    iv: Vec<u8>,
    cypher_key: Vec<u8>,
}

impl Display for PwHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!("Master IV: {:02X?} (len {})\n\
                IV: {:02X?} (len {})\n\
                Key {:02X?} (len {})",
                          self.master_iv, self.iv.len(), self.iv, self.iv.len(),
                          self.cypher_key, self.cypher_key.len());
        write!(f, "{}", str)
    }
}

impl PwHeader {
    fn new(raw_data: &Vec<u8>) -> Result<PwHeader, String> {
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
        let cypher_key = raw_data[12 + master_iv_len + iv_len..].to_vec();
        Ok(PwHeader {master_iv, iv, cypher_key})
    }
}

impl EncryptedFile {
    fn new(path: String) -> Result<EncryptedFile, String> {
        if !Path::new(&path).exists() {
            return Err(String::from("Path does not exist"));
        }

        let raw_data = fs::read(&path);
        match raw_data {
            Ok(data) => Ok(EncryptedFile {
                path,
                cypher_data: data,
            }),
            Err(msg) => Err(format!("Error reading file: {}", msg.to_string())),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    for argument in &args[1..] {
        println!("{}", argument);
    }

    if args.len() < 2 {
        println!("Please specify the path to a file");
        exit(1);
    }

    let file = &args[1];
    if !Path::exists(Path::new(file)) {
        println!("The path {} does not exist", file);
        exit(1);
    }

    let pw_file = match EncryptedFile::new(file.to_string()) {
        Ok(pw_file) => pw_file,
        Err(msg) => {
            println!("{}", msg);
            exit(1);
        },
    };

    let header = match PwHeader::new(&pw_file.cypher_data) {
        Ok(header) => header,
        Err(msg) => {
            println!("{}", msg);
            exit(1);
        }
    };

    println!("{}", header);
}
