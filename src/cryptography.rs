use std::fmt::Display;
use std::fs;
use std::num::NonZeroU32;
use std::path::Path;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher};
use ring::pbkdf2::{derive, Algorithm};
use secure_string::{SecureArray, SecureString, SecureVec};

static USE_LITTLE_ENDIAN: bool = true;
static PBKDF2_ALGO: Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA1;
static PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();
static AES_IV_LEN: usize = 16;
static AES_KEY_LEN: usize = 32;
static HMAC_SALT_LEN: usize = 8;
type AesIV = [u8; AES_IV_LEN];
type Salt = [u8; HMAC_SALT_LEN];


pub struct RawFile {
    path: String,
    cypher_data: Vec<u8>,
}

pub struct VaultData {
    iv: AesIV,
    cypher_master_key: Vec<u8>,
    salt: Salt
}

pub struct EncryptedFile {
    master_iv: AesIV,
    iv: AesIV,
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
    pub fn new(raw_data: &Vec<u8>) -> Result<VaultData, String> {
        if raw_data.len() < 8 {
            return Err(String::from("expected at least 8 bytes of header data"));
        }

        let iv_length = from_bytes(raw_data[0..4].try_into().unwrap()) as usize;
        if iv_length != AES_IV_LEN {
            return Err(format!("Expected IV length of {} bytes, got {}", AES_IV_LEN, iv_length));
        }

        let key_length = from_bytes(raw_data[4..8].try_into().unwrap()) as usize;
        if raw_data.len() < 8 + iv_length + key_length {
            return Err(format!(
                "Expected {} bytes of IV and {} bytes of key data but only got {} bytes of data",
                iv_length,
                key_length,
                raw_data.len()
            ));
        }

        let iv: [u8; AES_IV_LEN] = raw_data[8..8 + AES_IV_LEN].try_into().unwrap();
        let cypher_key = raw_data[8 + iv_length..8 + iv_length + key_length].to_vec();
        if raw_data.len() < 12 + iv_length + key_length + 4 {
            return Err(String::from("expected at least 4 additional bytes of salt length"));
        }

        let salt_length = from_bytes(
            raw_data[8 + iv_length + key_length..8 + iv_length + key_length + 4]
                .try_into().unwrap()) as usize;
        if salt_length != HMAC_SALT_LEN {
            return Err(format!("Expected salt of length {} bytes, got {}",
                               HMAC_SALT_LEN, salt_length));
        }
        if raw_data.len() < 12 + iv_length + key_length + salt_length {
            return Err(format!("Expected {} bytes of salt but only got {} bytes left",
                               salt_length, raw_data.len() - 12 - iv_length - key_length));
        }

        let salt = raw_data[12 + iv_length + key_length..
            12 + iv_length + key_length + HMAC_SALT_LEN].try_into().unwrap();
        Ok(VaultData {
            iv,
            cypher_master_key: cypher_key,
            salt
        })
    }
}

impl EncryptedFile {
    pub fn new(raw_data: &Vec<u8>) -> Result<EncryptedFile, String> {
        if raw_data.len() < 12 {
            return Err(String::from("Expected 12 bytes of header"));
        }

        let master_iv_len = from_bytes(raw_data[0..4].try_into().unwrap()) as usize;
        let iv_len = from_bytes(raw_data[4..8].try_into().unwrap()) as usize;
        if master_iv_len != AES_IV_LEN || iv_len != AES_IV_LEN {
            return Err(format!("Expected IV of length {} bytes, got {}", AES_IV_LEN, iv_len));
        }

        let key_len = from_bytes(raw_data[8..12].try_into().unwrap()) as usize;
        if raw_data.len() < 12 + master_iv_len + iv_len + key_len {
            return Err(format!(
                "Expected {} bytes of master IV, {} bytes of IV and {} bytes of key data but only \
                got {} bytes of data", master_iv_len, iv_len, key_len, raw_data.len()));
        }

        let master_iv = raw_data[12..12 + AES_IV_LEN].try_into().unwrap();
        let iv = raw_data[12 + AES_IV_LEN..12 + AES_IV_LEN + AES_IV_LEN].try_into().unwrap();
        let cypher_key =
            raw_data[12 + master_iv_len + iv_len..12 + master_iv_len + iv_len + key_len].to_vec();
        let data = raw_data[12 + master_iv_len + iv_len + key_len..].to_vec();
        Ok(EncryptedFile { master_iv, iv, cypher_key, cypher_data: data })
    }
}

impl RawFile {
    pub fn new(path: &String) -> Result<RawFile, String> {
        if !Path::new(&path).exists() {
            return Err(String::from("Path does not exist"));
        }

        let raw_data = fs::read(&path);
        match raw_data {
            Ok(data) => Ok(RawFile {
                path: path.clone(),
                cypher_data: data,
            }),
            Err(msg) => Err(format!("Error reading file: {}", msg.to_string())),
        }
    }
}

pub fn from_bytes(bytes: [u8; 4]) -> u32 {
    if USE_LITTLE_ENDIAN {
        return u32::from_le_bytes(bytes);
    }

    u32::from_be_bytes(bytes)
}

pub fn to_bytes(value: u32) -> [u8; 4] {
    if USE_LITTLE_ENDIAN {
        return value.to_le_bytes();
    }

    value.to_ne_bytes()
}

pub fn raw(string: &SecureString) -> &[u8] {
    let us = string.unsecure();
    us.as_bytes()
}

pub fn get_master_key(master_pw: &SecureString, vault_data: &VaultData) -> Result<SecureVec<u8>, String> {
    let (cypher_key, rem) = vault_data.cypher_master_key.as_chunks::<48>();
    if cypher_key.len() != 1 || rem.len() != 0 {
        return Err(format!("Expected encrypted master key of size 48 but got {} bytes", vault_data.cypher_master_key.len()));
    }

    let cypher_key: [u8; 48] = cypher_key[0];
    let mut key = [0; AES_KEY_LEN];
    derive(PBKDF2_ALGO, PBKDF2_ITERATIONS, &vault_data.salt, raw(master_pw), & mut key);
    match decrypt(Cipher::aes_256_cbc(), &key, Some(&vault_data.iv), &cypher_key) {
        Ok(key) => Ok(SecureVec::new(key)),
        Err(msg) => Err(format!("Error retrieving master key: {}", msg.to_string()))
    }
}

pub fn decrypt_text_file(file: &EncryptedFile, master_key: &SecureVec<u8>) -> Result<SecureVec<u8>, String> {
    let key = match decrypt(Cipher::aes_256_cbc(), master_key.unsecure(),
                            Some(&file.master_iv), &file.cypher_key) {
        Ok(key) => SecureVec::from(key),
        Err(msg) => return Err(format!("Error retrieving file key: {}", msg.to_string()))
    };

    let key_len = key.unsecure().len();
    if key_len != AES_KEY_LEN {
        return Err(format!("Wrong file key length {key_len}, expected {AES_KEY_LEN}"));
    }

    match decrypt(Cipher::aes_256_cbc(), key.unsecure(), Some(&file.iv), &file.cypher_data) {
        Ok(data) => Ok(SecureVec::from(data)),
        Err(msg) => Err(format!("Error decrypting data: {}", msg.to_string()))
    }
}

pub fn parse<T>(file_path: &String, new: fn(&Vec<u8>) -> Result<T, String>) -> Result<T, String> {
    let file = match RawFile::new(file_path) {
        Ok(file) => file,
        Err(msg) => return Err(msg)
    };

    match new(&file.cypher_data) {
        Ok(file) => Ok(file),
        Err(msg) => Err(msg)
    }
}

pub fn generate_random_data<const L:usize>() -> SecureArray<u8, L> {
    let mut data = SecureArray::new([0u8; L]);
    rand_bytes(&mut data.unsecure_mut()).unwrap();
    data
}

pub fn encrypt_text_file(data: &SecureString, master_key: &SecureVec<u8>) -> Result<Vec<u8>, String> {
    let file_key = generate_random_data::<AES_KEY_LEN>();
    let file_iv = generate_random_data::<AES_IV_LEN>();
    let master_iv = generate_random_data::<AES_IV_LEN>();
    let mut ret = Vec::<u8>::new();
    let mut encrypted_key = match encrypt(Cipher::aes_256_cbc(), master_key.unsecure(),
                                          Some(master_iv.unsecure()), file_key.unsecure()) {
        Ok(key) => key,
        Err(msg) => return Err(format!("Failed to encrypt file key: {}", msg.to_string()))
    };

    ret.extend(to_bytes(master_iv.unsecure().len() as u32));
    ret.extend(to_bytes(file_iv.unsecure().len() as u32));
    ret.extend(to_bytes(encrypted_key.len() as u32));
    ret.extend(master_iv.unsecure());
    ret.extend(file_iv.unsecure());
    ret.append(&mut encrypted_key);

    let mut encrypted_data = match encrypt(Cipher::aes_256_cbc(), file_key.unsecure(),
                                           Some(file_iv.unsecure()), data.unsecure().as_bytes()) {
        Ok(data) => data,
        Err(msg) => return Err(format!("Failed to encrypt data: {}", msg.to_string()))
    };

    ret.append(&mut encrypted_data);
    Ok(ret)
}
