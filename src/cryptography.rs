use std::fmt::{format, Debug, Display};
use std::fs;
use std::fs::File;
use std::io::{Read, Seek};
use std::io::SeekFrom::{Current, Start};
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


pub struct VaultData {
    iv: AesIV,
    cypher_master_key: Vec<u8>,
    salt: Salt
}

pub struct EncryptedFile {
    path: String,
    master_iv: AesIV,
    iv: AesIV,
    cypher_key: Vec<u8>,
    data_offset: usize
}

impl Display for EncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "Header:\n\
            \tMaster IV: {:02X?} (len {})\n\
            \tIV: {:02X?} (len {})\n\
            \tKey {:02X?} (len {})\n\
            Data offset: {} ",
            self.master_iv, self.iv.len(), self.iv, self.iv.len(), self.cypher_key,
            self.cypher_key.len(), self.data_offset
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
    pub fn new(path: &String) -> Result<VaultData, String> {
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(msg) => { return Err(format!("Could not open file {path}: {msg}")); }
        };

        let header = read_bytes(& mut file, 8, Start(0), "header")?;
        let iv_length = from_bytes(header[0..4].try_into().unwrap()) as usize;
        if iv_length != AES_IV_LEN {
            return Err(format!("Expected IV length of {} bytes, got {}", AES_IV_LEN, iv_length));
        }

        let key_length = from_bytes(header[4..8].try_into().unwrap()) as usize;
        let iv = read_bytes(& mut file, AES_IV_LEN, Start(8), "iv")?.try_into().unwrap();
        let cypher_key = read_bytes(& mut file, key_length, Current(0), "cypher key")?;
        let salt_length = read_bytes(&mut file, 4, Current(0), "salt len")?.try_into().unwrap();
        let salt_length = from_bytes(salt_length) as usize;
        if salt_length != HMAC_SALT_LEN {
            return Err(format!("Expected salt of length {} bytes, got {}",
                               HMAC_SALT_LEN, salt_length));
        }
        let salt = read_bytes(& mut file, HMAC_SALT_LEN, Current(0), "salt")?.try_into().unwrap();
        Ok(VaultData { iv, cypher_master_key: cypher_key, salt })
    }
}

fn read_bytes(file: &mut fs::File, len: usize, offset: std::io::SeekFrom, msg: &str) -> Result<Vec<u8>, String> {
    if let Err(err) = file.seek(offset) {
        return Err(format!("Could not seek specified offset: {err}"));
    }

    let mut ret = vec![0u8; len];
    if let Err(err) = file.read_exact(&mut ret) {
        return Err(format!("Could not read {len} bytes for {msg}: {}", err.to_string()));
    }

    Ok(ret)
}

fn read_all(file: &String, offset: std::io::SeekFrom) -> Result<Vec<u8>, String> {
    let mut file_handle = match File::open(file) {
        Ok(file) => file,
        Err(msg) => {return Err(format!("Failed to open file {file}: {}", msg.to_string()))}
    };

    if let Err(err) = file_handle.seek(offset) {
        return Err(format!("Could not seek specified offset: {err}"));
    }

    let mut ret = Vec::<u8>::new();
    match file_handle.read_to_end(&mut ret) {
        Ok(_) => Ok(ret),
        Err(msg) => Err(format!("Failed reading file contents: {}", msg.to_string()))
    }
}

impl EncryptedFile {
    pub fn new(path: &String) -> Result<EncryptedFile, String> {
        if !Path::new(&path).exists() {
            return Err(String::from("Path does not exist"));
        }

        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(msg) => return Err(format!("Could not open file: {}", msg))
        };

        let header = read_bytes(&mut file, 12, Start(0), "header")?;
        let master_iv_len = from_bytes(header[0..4].try_into().unwrap()) as usize;
        let iv_len = from_bytes(header[4..8].try_into().unwrap()) as usize;
        if master_iv_len != AES_IV_LEN || iv_len != AES_IV_LEN {
            return Err(format!("Expected IV of length {} bytes, got {}", AES_IV_LEN, iv_len));
        }

        let key_len = from_bytes(header[8..12].try_into().unwrap()) as usize;
        let master_iv = read_bytes(& mut file, AES_IV_LEN, Start(12), "master iv")?.try_into().unwrap();
        let iv = read_bytes(& mut file, AES_IV_LEN, Current(0), "file iv")?.try_into().unwrap();
        let cypher_key = read_bytes(& mut file, key_len, Current(0), "cypher key")?;
        let data_offset = 12 + 2 * AES_IV_LEN + key_len;
        Ok(EncryptedFile { path: path.clone(), master_iv, iv, cypher_key, data_offset })
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

    let cypher_data = read_all(&file.path, Start(file.data_offset as u64))?;
    match decrypt(Cipher::aes_256_cbc(), key.unsecure(), Some(&file.iv), &cypher_data) {
        Ok(data) => Ok(SecureVec::from(data)),
        Err(msg) => Err(format!("Error decrypting data: {}", msg.to_string()))
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
