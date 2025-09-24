use crate::error;
use crate::error::MpwError;
use crate::{define, io};
use constcat::concat;
use cryptostream::write::{Decryptor, Encryptor};
use openssl::symm::{Cipher, decrypt, encrypt};
use ring::pbkdf2::{Algorithm, derive};
use secure_string::{SecureArray, SecureString, SecureVec};
use std::fmt::Display;
use std::fs;
use std::io::SeekFrom::{Current, Start};
use std::io::{BufWriter, Read, Seek, Write};
use std::num::NonZeroU32;
use std::path::Path;

define!(USE_LITTLE_ENDIAN: bool = true);
define!(PBKDF2_ALGO: Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA1);
define!(PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap());
define!(AES_IV_LEN: usize = 16);
define!(AES_KEY_LEN: usize = 32);
define!(HMAC_SALT_LEN: usize = 8);
const OPEN_SSL_BAD_DECRYPT: u64 = 0x1C800064;
type AesIV = [u8; AES_IV_LEN.value];
type Salt = [u8; HMAC_SALT_LEN.value];
pub type AesKey = SecureArray<u8, { AES_KEY_LEN.value }>;

pub struct VaultData {
    iv: AesIV,
    cypher_master_key: Vec<u8>,
    salt: Salt,
}

pub struct FileHeader {
    pub master_iv: AesIV,
    pub iv: AesIV,
    pub cypher_key: Vec<u8>,
}

impl Display for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "Header:\n\
            \tMaster IV: {:02X?} (len {})\n\
            \tIV: {:02X?} (len {})\n\
            \tKey {:02X?} (len {})\n\
            Data offset: {} ",
            self.master_iv,
            self.master_iv.len(),
            self.iv,
            self.iv.len(),
            self.cypher_key,
            self.cypher_key.len(),
            self.data_offset()
        );
        write!(f, "{}", str)
    }
}

impl From<FileHeader> for Vec<u8> {
    fn from(mut value: FileHeader) -> Self {
        let mut ret = Vec::new();
        ret.extend(util::to_bytes(value.master_iv.len() as u32));
        ret.extend(util::to_bytes(value.iv.len() as u32));
        ret.extend(util::to_bytes(value.cypher_key.len() as u32));
        ret.extend(value.master_iv);
        ret.extend(value.iv);
        ret.append(&mut value.cypher_key);
        ret
    }
}

impl Display for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "IV: {:02X?} (len {})\n\
             Key {:02X?} (len {})\n\
             Salt {:02X?} (len {})",
            self.iv,
            self.iv.len(),
            self.cypher_master_key,
            self.cypher_master_key.len(),
            self.salt,
            self.salt.len()
        );
        write!(f, "{}", str)
    }
}

impl VaultData {
    pub fn new(path: &std::path::Path) -> error::Result<VaultData> {
        type HErr = error::InvalidHeader;
        let mut file = fs::File::open(path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to open vault file: {}", e.to_string()),
            )
        })?;

        let header = io::read_bytes(&mut file, 8, Start(0)).map_err(HErr::Io)?;
        let iv_length = util::from_bytes(header[0..4].try_into().unwrap()) as usize;
        if iv_length != AES_IV_LEN.value {
            return HErr::Format {
                expected: concat!(AES_IV_LEN.as_string, " bytes of iv"),
                found: iv_length.to_string(),
            }
            .into();
        }

        let key_length = util::from_bytes(header[4..8].try_into().unwrap()) as usize;
        let iv = io::read_bytes(&mut file, AES_IV_LEN.value, Start(8))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let cypher_key = io::read_bytes(&mut file, key_length, Current(0)).map_err(HErr::Io)?;
        let salt_length = io::read_bytes(&mut file, 4, Current(0))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let salt_length = util::from_bytes(salt_length) as usize;
        if salt_length != HMAC_SALT_LEN.value {
            return error::InvalidHeader::Format {
                expected: concat!(HMAC_SALT_LEN.as_string, " bytes of salt"),
                found: salt_length.to_string(),
            }
            .into();
        }
        let salt = io::read_bytes(&mut file, HMAC_SALT_LEN.value, Current(0))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        Ok(VaultData {
            iv,
            cypher_master_key: cypher_key,
            salt,
        })
    }
}

impl FileHeader {
    pub fn new(path: &Path) -> error::Result<FileHeader> {
        type HErr = error::InvalidHeader;
        let mut file = fs::File::open(&path)?;
        let header = io::read_bytes(&mut file, 12, Start(0)).map_err(HErr::Io)?;
        let master_iv_len = util::from_bytes(header[0..4].try_into().unwrap()) as usize;
        let iv_len = util::from_bytes(header[4..8].try_into().unwrap()) as usize;
        if master_iv_len != AES_IV_LEN.value || iv_len != AES_IV_LEN.value {
            return HErr::Format {
                expected: constcat::concat!(AES_IV_LEN.as_string, " bytes of iv"),
                found: iv_len.to_string(),
            }
            .into();
        }

        let key_len = util::from_bytes(header[8..12].try_into().unwrap()) as usize;
        let master_iv = io::read_bytes(&mut file, AES_IV_LEN.value, Start(12))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let iv = io::read_bytes(&mut file, AES_IV_LEN.value, Current(0))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let cypher_key = io::read_bytes(&mut file, key_len, Current(0)).map_err(HErr::Io)?;
        Ok(FileHeader {
            master_iv,
            iv,
            cypher_key,
        })
    }

    pub fn data_offset(&self) -> usize {
        12 + 2 * AES_IV_LEN.value + self.cypher_key.len()
    }
}

mod util {
    use crate::cryptography::{
        AES_IV_LEN, AES_KEY_LEN, AesIV, AesKey, HMAC_SALT_LEN, Salt, USE_LITTLE_ENDIAN,
    };
    use openssl::rand::rand_bytes;
    use secure_string::{SecureArray, SecureString, SecureVec};

    pub fn from_bytes(bytes: [u8; 4]) -> u32 {
        if USE_LITTLE_ENDIAN.value {
            return u32::from_le_bytes(bytes);
        }

        u32::from_be_bytes(bytes)
    }

    pub fn to_bytes(value: u32) -> [u8; 4] {
        if USE_LITTLE_ENDIAN.value {
            return value.to_le_bytes();
        }

        value.to_ne_bytes()
    }

    pub fn raw(string: &SecureString) -> &[u8] {
        let us = string.unsecure();
        us.as_bytes()
    }

    pub fn generate_random_data<const L: usize>() -> SecureArray<u8, L> {
        let mut data = SecureArray::new([0u8; L]);
        rand_bytes(&mut data.unsecure_mut()).unwrap();
        data
    }

    pub fn generate_key() -> AesKey {
        generate_random_data::<{ AES_KEY_LEN.value }>().into()
    }

    pub fn generate_iv() -> AesIV {
        generate_random_data::<{ AES_IV_LEN.value }>()
            .unsecure()
            .try_into()
            .unwrap()
    }

    pub fn generate_salt() -> Salt {
        generate_random_data::<{ HMAC_SALT_LEN.value }>()
            .unsecure()
            .try_into()
            .unwrap()
    }

    pub fn to_key(src: SecureVec<u8>) -> Result<AesKey, crate::error::MpwError> {
        Ok(AesKey::new(src.unsecure().try_into().map_err(|_| {
            crate::error::MpwError::InvalidKeyLength {
                expected: AES_KEY_LEN.value,
                found: src.unsecure().len(),
            }
        })?))
    }
}

pub fn get_master_key(master_pw: SecureString, vault_data: &VaultData) -> error::Result<AesKey> {
    type HErr = error::InvalidHeader;
    let (cypher_key, rem) = vault_data.cypher_master_key.as_chunks::<48>();
    if cypher_key.len() != 1 || rem.len() != 0 {
        return HErr::Format {
            expected: concat!(48, " bytes of encrypted master key"),
            found: vault_data.cypher_master_key.len().to_string(),
        }
        .into();
    }

    let cypher_key: [u8; 48] = cypher_key[0];
    let mut key = [0; AES_KEY_LEN.value];
    derive(
        PBKDF2_ALGO.value,
        PBKDF2_ITERATIONS.value,
        &vault_data.salt,
        util::raw(&master_pw),
        &mut key,
    );
    match decrypt(
        Cipher::aes_256_cbc(),
        &key,
        Some(&vault_data.iv),
        &cypher_key,
    ) {
        Ok(key) => Ok(SecureArray::new(key.try_into().unwrap())),
        Err(msg) => {
            if msg
                .errors()
                .first()
                .is_some_and(|e| e.code() == OPEN_SSL_BAD_DECRYPT)
            {
                return MpwError::WrongPassword.into();
            }

            MpwError::Cryptography(msg.into()).into()
        }
    }
}

pub fn decrypt_file(
    path: &Path,
    master_key: &AesKey,
) -> error::Result<SecureVec<u8>> {
    let header = FileHeader::new(path)?;
    let key = decrypt_file_header(&header, &master_key)?;
    let cypher_data = io::read_all(path, Start(header.data_offset() as u64))?;
    match decrypt(
        Cipher::aes_256_cbc(),
        key.unsecure(),
        Some(&header.iv),
        &cypher_data,
    ) {
        Ok(data) => Ok(SecureVec::from(data)),
        Err(msg) => {
            if msg
                .errors()
                .first()
                .is_some_and(|e| e.code() == OPEN_SSL_BAD_DECRYPT)
            {
                return MpwError::WrongPassword.into();
            }

            MpwError::Cryptography(msg.into()).into()
        }
    }
}

pub fn generate_file_header(master_key: &AesKey) -> error::Result<(FileHeader, AesKey, AesIV)> {
    let file_key = util::generate_key();
    let file_iv = util::generate_iv();
    let master_iv = util::generate_iv();
    let encrypted_key = encrypt(
        Cipher::aes_256_cbc(),
        master_key.unsecure(),
        Some(&master_iv),
        file_key.unsecure(),
    )?;
    Ok((FileHeader { master_iv, iv: file_iv, cypher_key: encrypted_key }, file_key, file_iv))
}

pub fn decrypt_file_header(header: &FileHeader, master_key: &AesKey) -> error::Result<AesKey> {
    let key = decrypt(
        Cipher::aes_256_cbc(),
        master_key.unsecure(),
        Some(&header.master_iv),
        &header.cypher_key,
    )
    .map(SecureVec::new)?;
    Ok(util::to_key(key)?)
}

pub fn encrypt_text(data: SecureString, master_key: &AesKey) -> error::Result<Vec<u8>> {
    let (header, file_key, _) = generate_file_header(master_key)?;
    let mut encrypted_data = encrypt(
        Cipher::aes_256_cbc(),
        file_key.unsecure(),
        Some(&header.iv),
        data.unsecure().as_bytes(),
    )?;
    let mut raw: Vec<u8> = header.into();
    raw.append(&mut encrypted_data);
    Ok(raw)
}

pub fn crypto_write<Source, Dest>(
    source: Source,
    dest: &mut Dest,
    key: &AesKey,
    iv: &AesIV,
) -> error::Result<()>
where
    Source: Read + Write + Seek,
    Dest: Write,
{
    let mut cs = Encryptor::new(dest, Cipher::aes_256_cbc(), key.unsecure(), iv)?;
    let (mut source, source_size) = io::transfer_data(source, &mut cs)?;
    source.seek(Start(0))?;
    let mut bw_source = BufWriter::new(source);
    bw_source.write_all(&vec![0u8; source_size])?;
    bw_source.flush()?;
    cs.finish()?;
    Ok(())
}

pub fn crypto_read<Source, Dest>(
    source: Source,
    dest: &mut Dest,
    key: &AesKey,
    iv: &AesIV,
) -> error::Result<()>
where
    Source: Read,
    Dest: Write,
{
    let mut cs = Decryptor::new(dest, Cipher::aes_256_cbc(), key.unsecure(), iv)?;
    io::transfer_data(source, &mut cs)?;
    cs.finish()?;
    Ok(())
}
