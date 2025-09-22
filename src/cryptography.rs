use std::fmt::{Display};
use std::fs;
use std::io::{Read, Write, Seek, BufWriter};
use std::io::SeekFrom::{Current, Start};
use std::num::NonZeroU32;
use std::path::Path;
use openssl::symm::{decrypt, encrypt, Cipher};
use ring::pbkdf2::{derive, Algorithm};
use secure_string::{SecureArray, SecureString, SecureVec};
use cryptostream::write::{Encryptor, Decryptor};
use crate::io;

static USE_LITTLE_ENDIAN: bool = true;
static PBKDF2_ALGO: Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA1;
static PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();
static AES_IV_LEN: usize = 16;
static AES_KEY_LEN: usize = 32;
static HMAC_SALT_LEN: usize = 8;
type AesIV = [u8; AES_IV_LEN];
type Salt = [u8; HMAC_SALT_LEN];
pub type AesKey = SecureArray<u8, AES_KEY_LEN>;


pub struct VaultData {
    iv: AesIV,
    cypher_master_key: Vec<u8>,
    salt: Salt
}

pub struct EncryptedFile {
    pub path: String,
    pub master_iv: AesIV,
    pub iv: AesIV,
    pub cypher_key: Vec<u8>,
    pub data_offset: usize
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

        let header = io::read_bytes(& mut file, 8, Start(0), "header")?;
        let iv_length = util::from_bytes(header[0..4].try_into().unwrap()) as usize;
        if iv_length != AES_IV_LEN {
            return Err(format!("Expected IV length of {} bytes, got {}", AES_IV_LEN, iv_length));
        }

        let key_length = util::from_bytes(header[4..8].try_into().unwrap()) as usize;
        let iv = io::read_bytes(& mut file, AES_IV_LEN, Start(8), "iv")?.try_into().unwrap();
        let cypher_key = io::read_bytes(& mut file, key_length, Current(0), "cypher key")?;
        let salt_length = io::read_bytes(&mut file, 4, Current(0), "salt len")?.try_into().unwrap();
        let salt_length = util::from_bytes(salt_length) as usize;
        if salt_length != HMAC_SALT_LEN {
            return Err(format!("Expected salt of length {} bytes, got {}",
                               HMAC_SALT_LEN, salt_length));
        }
        let salt = io::read_bytes(& mut file, HMAC_SALT_LEN, Current(0), "salt")?.try_into().unwrap();
        Ok(VaultData { iv, cypher_master_key: cypher_key, salt })
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

        let header = io::read_bytes(&mut file, 12, Start(0), "header")?;
        let master_iv_len = util::from_bytes(header[0..4].try_into().unwrap()) as usize;
        let iv_len = util::from_bytes(header[4..8].try_into().unwrap()) as usize;
        if master_iv_len != AES_IV_LEN || iv_len != AES_IV_LEN {
            return Err(format!("Expected IV of length {} bytes, got {}", AES_IV_LEN, iv_len));
        }

        let key_len = util::from_bytes(header[8..12].try_into().unwrap()) as usize;
        let master_iv = io::read_bytes(& mut file, AES_IV_LEN, Start(12), "master iv")?.try_into().unwrap();
        let iv = io::read_bytes(& mut file, AES_IV_LEN, Current(0), "file iv")?.try_into().unwrap();
        let cypher_key = io::read_bytes(& mut file, key_len, Current(0), "cypher key")?;
        let data_offset = 12 + 2 * AES_IV_LEN + key_len;
        Ok(EncryptedFile { path: path.clone(), master_iv, iv, cypher_key, data_offset })
    }
}

mod util {
    use openssl::rand::rand_bytes;
    use secure_string::{SecureArray, SecureString};
    use crate::cryptography::{AesIV, AesKey, Salt, USE_LITTLE_ENDIAN, AES_KEY_LEN, AES_IV_LEN, HMAC_SALT_LEN};

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

    pub fn generate_random_data<const L:usize>() -> SecureArray<u8, L> {
        let mut data = SecureArray::new([0u8; L]);
        rand_bytes(&mut data.unsecure_mut()).unwrap();
        data
    }

    pub fn generate_key() -> AesKey {
        generate_random_data::<AES_KEY_LEN>().into()
    }

    pub fn generate_iv() -> AesIV {
        generate_random_data::<AES_IV_LEN>().unsecure().try_into().unwrap()
    }

    pub fn generate_salt() -> Salt {
        generate_random_data::<HMAC_SALT_LEN>().unsecure().try_into().unwrap()
    }
}


pub fn get_master_key(master_pw: &SecureString, vault_data: &VaultData) -> Result<AesKey, String> {
    let (cypher_key, rem) = vault_data.cypher_master_key.as_chunks::<48>();
    if cypher_key.len() != 1 || rem.len() != 0 {
        return Err(format!("Expected encrypted master key of size 48 but got {} bytes", vault_data.cypher_master_key.len()));
    }

    let cypher_key: [u8; 48] = cypher_key[0];
    let mut key = [0; AES_KEY_LEN];
    derive(PBKDF2_ALGO, PBKDF2_ITERATIONS, &vault_data.salt, util::raw(master_pw), & mut key);
    match decrypt(Cipher::aes_256_cbc(), &key, Some(&vault_data.iv), &cypher_key) {
        Ok(key) => Ok(SecureArray::new(key.try_into().unwrap())),
        Err(msg) => Err(format!("Error retrieving master key: {}", msg.to_string()))
    }
}

pub fn decrypt_text_file(file: &EncryptedFile, master_key: &AesKey) -> Result<SecureVec<u8>, String> {
    let key = match decrypt(Cipher::aes_256_cbc(), master_key.unsecure(),
                            Some(&file.master_iv), &file.cypher_key) {
        Ok(key) => SecureVec::from(key),
        Err(msg) => return Err(format!("Error retrieving file key: {}", msg.to_string()))
    };

    let key_len = key.unsecure().len();
    if key_len != AES_KEY_LEN {
        return Err(format!("Wrong file key length {key_len}, expected {AES_KEY_LEN}"));
    }

    let cypher_data = io::read_all(&file.path, Start(file.data_offset as u64))?;
    match decrypt(Cipher::aes_256_cbc(), key.unsecure(), Some(&file.iv), &cypher_data) {
        Ok(data) => Ok(SecureVec::from(data)),
        Err(msg) => Err(format!("Error decrypting data: {}", msg.to_string()))
    }
}

pub fn generate_file_header(master_key: &AesKey) -> Result<(Vec<u8>, AesKey, AesIV), String> {
    let file_key = util::generate_key();
    let file_iv = util::generate_iv();
    let master_iv = util::generate_iv();
    let mut ret = Vec::<u8>::new();
    let mut encrypted_key = match encrypt(Cipher::aes_256_cbc(), master_key.unsecure(),
                                          Some(&master_iv), file_key.unsecure()) {
        Ok(key) => key,
        Err(msg) => return Err(format!("Failed to encrypt file key: {}", msg.to_string()))
    };

    ret.extend(util::to_bytes(master_iv.len() as u32));
    ret.extend(util::to_bytes(file_iv.len() as u32));
    ret.extend(util::to_bytes(encrypted_key.len() as u32));
    ret.extend(master_iv);
    ret.extend(file_iv);
    ret.append(&mut encrypted_key);
    Ok((ret, file_key, file_iv))
}

pub fn encrypt_text_file(data: &SecureString, master_key: &AesKey) -> Result<Vec<u8>, String> {
    let (mut contents, file_key, file_iv) = generate_file_header(master_key)?;
    let mut encrypted_data = match encrypt(Cipher::aes_256_cbc(), file_key.unsecure(),
                                           Some(&file_iv), data.unsecure().as_bytes()) {
        Ok(data) => data,
        Err(msg) => return Err(format!("Failed to encrypt data: {}", msg.to_string()))
    };

    contents.append(&mut encrypted_data);
    Ok(contents)
}

pub fn crypto_write<Source, Dest>(source: Source, dest: &mut Dest, key: &AesKey, iv: &AesIV) -> Result<(), String>
where
    Source: Read + Write + Seek,
    Dest: Write
{
    let mut cs = Encryptor::new(dest, Cipher::aes_256_cbc(), key.unsecure(), iv)
        .map_err(|err| format!("failed to create encryptor: {}", err.to_string()))?;
    let (mut source, source_size) = io::transfer_data(source, &mut cs)?;
    source.seek(Start(0)).map_err(|err| format!("failed to seek to start of source buffer: {}", err.to_string()))?;
    let mut bw_source = BufWriter::new(source);
    bw_source.write_all(&vec![0u8; source_size]).map_err(|err| format!("failed to zero source buffer: {}", err.to_string()))?;
    bw_source.flush().map_err(|err| format!("failed to flush source buffer: {}", err.to_string()))?;
    cs.finish().map_err(|err| format!("failed to finish encryption: {}", err.to_string()))?;
    Ok(())
}

pub fn crypto_read<Source, Dest>(source: Source, dest: &mut Dest, key: &AesKey, iv: &AesIV) -> Result<(), String>
where
    Source: Read,
    Dest: Write
{
    let mut cs = Decryptor::new(dest, Cipher::aes_256_cbc(), key.unsecure(), iv)
        .map_err(|err| format!("failed to create decryptor: {}", err.to_string()))?;
    io::transfer_data(source, &mut cs)?;
    cs.finish().map_err(|err| format!("failed to finish decryption: {}", err.to_string()))?;
    Ok(())
}