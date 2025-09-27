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
use std::io::{BufWriter, Cursor, Read, Seek, Write};
use std::num::NonZeroU32;
use std::path::Path;

// Constants and aliases

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

// Structures

pub struct VaultData {
    iv: AesIV,
    cipher_master_key: Vec<u8>,
    salt: Salt,
}

pub struct FileHeader {
    pub master_iv: AesIV,
    pub iv: AesIV,
    pub cipher_key: Vec<u8>,
}

// Traits
// --- VaultData
impl Display for VaultData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "IV: {:02X?} (len {})\n\
             Key {:02X?} (len {})\n\
             Salt {:02X?} (len {})",
            self.iv,
            self.iv.len(),
            self.cipher_master_key,
            self.cipher_master_key.len(),
            self.salt,
            self.salt.len()
        );
        write!(f, "{}", str)
    }
}

impl From<VaultData> for Vec<u8> {
    fn from(mut value: VaultData) -> Self {
        let mut ret = Vec::with_capacity(
            12 + value.iv.len() + value.cipher_master_key.len() + value.salt.len(),
        );
        ret.extend(util::to_bytes(value.iv.len() as u32));
        ret.extend(util::to_bytes(value.cipher_master_key.len() as u32));
        ret.extend(value.iv);
        ret.append(&mut value.cipher_master_key);
        ret.extend(util::to_bytes(value.salt.len() as u32));
        ret.extend(value.salt);
        ret
    }
}

impl TryFrom<&[u8]> for VaultData {
    type Error = MpwError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        VaultData::new(Cursor::new(value))
    }
}

impl TryFrom<Vec<u8>> for VaultData {
    type Error = MpwError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VaultData::new(Cursor::new(value))
    }
}

// --- FileHeader
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
            self.cipher_key,
            self.cipher_key.len(),
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
        ret.extend(util::to_bytes(value.cipher_key.len() as u32));
        ret.extend(value.master_iv);
        ret.extend(value.iv);
        ret.append(&mut value.cipher_key);
        ret
    }
}

impl TryFrom<&[u8]> for FileHeader {
    type Error = MpwError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        FileHeader::new(Cursor::new(value))
    }
}

impl TryFrom<Vec<u8>> for FileHeader {
    type Error = MpwError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        FileHeader::new(Cursor::new(value))
    }
}

// Structure method implementations
impl VaultData {
    pub fn new<T: Read + Seek>(mut data: T) -> error::Result<VaultData> {
        type HErr = error::InvalidHeader;

        let header = io::read_bytes(&mut data, 8, Start(0)).map_err(HErr::Io)?;
        let iv_length = util::from_bytes(header[0..4].try_into().unwrap()) as usize;
        if iv_length != AES_IV_LEN.value {
            return HErr::Format {
                expected: concat!(AES_IV_LEN.as_string, " bytes of iv"),
                found: iv_length.to_string(),
            }
            .into();
        }

        let key_length = util::from_bytes(header[4..8].try_into().unwrap()) as usize;
        let iv = io::read_bytes(&mut data, AES_IV_LEN.value, Start(8))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let cipher_key = io::read_bytes(&mut data, key_length, Current(0)).map_err(HErr::Io)?;
        let salt_length = io::read_bytes(&mut data, 4, Current(0))
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
        let salt = io::read_bytes(&mut data, HMAC_SALT_LEN.value, Current(0))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        Ok(VaultData {
            iv,
            cipher_master_key: cipher_key,
            salt,
        })
    }
}

impl FileHeader {
    pub fn new<T: Read + Seek>(mut data: T) -> error::Result<FileHeader> {
        type HErr = error::InvalidHeader;
        let header = io::read_bytes(&mut data, 12, Start(0)).map_err(HErr::Io)?;
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
        let master_iv = io::read_bytes(&mut data, AES_IV_LEN.value, Start(12))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let iv = io::read_bytes(&mut data, AES_IV_LEN.value, Current(0))
            .map_err(HErr::Io)?
            .try_into()
            .unwrap();
        let cipher_key = io::read_bytes(&mut data, key_len, Current(0)).map_err(HErr::Io)?;
        Ok(FileHeader {
            master_iv,
            iv,
            cipher_key,
        })
    }

    pub fn data_offset(&self) -> usize {
        12 + 2 * AES_IV_LEN.value + self.cipher_key.len()
    }
}


// utility

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


// main methods

pub fn generate_key_from_password(password: &SecureString, salt: &Salt) -> AesKey {
    let mut key = AesKey::new([0u8; AES_KEY_LEN.value]);
    derive(
        PBKDF2_ALGO.value,
        PBKDF2_ITERATIONS.value,
        salt,
        util::raw(password),
        key.unsecure_mut(),
    );
    key
}

pub fn get_master_key(master_pw: SecureString, vault_data: &VaultData) -> error::Result<AesKey> {
    type HErr = error::InvalidHeader;
    let (cipher_key, rem) = vault_data.cipher_master_key.as_chunks::<48>();
    if cipher_key.len() != 1 || rem.len() != 0 {
        return HErr::Format {
            expected: concat!(48, " bytes of encrypted master key"),
            found: vault_data.cipher_master_key.len().to_string(),
        }
        .into();
    }

    let cipher_key: [u8; 48] = cipher_key[0];
    let key = generate_key_from_password(&master_pw, &vault_data.salt);
    match decrypt(
        Cipher::aes_256_cbc(),
        key.unsecure(),
        Some(&vault_data.iv),
        &cipher_key,
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

pub fn decrypt_text_from_file(path: &Path, master_key: &AesKey) -> error::Result<SecureString> {
    let cipher_data = io::read_all(path, Start(0))?;
    decrypt_text(&cipher_data, master_key)
}

pub fn encrypt_text_to_file(
    text: SecureString,
    path: &Path,
    master_key: &AesKey,
) -> error::Result<()> {
    let cipher_text = encrypt_text(text, master_key)?;
    let mut file = fs::File::create(path)?;
    file.write_all(&cipher_text)?;
    Ok(())
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
    Ok((
        FileHeader {
            master_iv,
            iv: file_iv,
            cipher_key: encrypted_key,
        },
        file_key,
        file_iv,
    ))
}

pub fn decrypt_file_header(header: &FileHeader, master_key: &AesKey) -> error::Result<AesKey> {
    let key = decrypt(
        Cipher::aes_256_cbc(),
        master_key.unsecure(),
        Some(&header.master_iv),
        &header.cipher_key,
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

pub fn decrypt_text(data: &[u8], master_key: &AesKey) -> error::Result<SecureString> {
    let header = FileHeader::try_from(data)?;
    let key = decrypt_file_header(&header, master_key)?;
    let cipher_data = &data[header.data_offset()..];
    let decrypted_data = decrypt(
        Cipher::aes_256_cbc(),
        key.unsecure(),
        Some(&header.iv),
        cipher_data,
    )?;
    Ok(SecureString::from(String::from_utf8(decrypted_data)?))
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::cryptography::util::{generate_iv, generate_key, generate_salt};
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    #[test]
    fn test_util_to_bytes() {
        if USE_LITTLE_ENDIAN.value {
            assert_eq!(util::to_bytes(612352), [0x00, 0x58, 0x09, 0x00]);
        } else {
            assert_eq!(util::to_bytes(612352), [0x00, 0x09, 0x58, 0x00]);
        }
    }

    #[test]
    fn test_util_from_bytes() {
        if USE_LITTLE_ENDIAN.value {
            assert_eq!(util::from_bytes([0x00, 0x58, 0x09, 0x00]), 612352);
        } else {
            assert_eq!(util::from_bytes([0x00, 0x09, 0x58, 0x00]), 612352);
        }
    }

    #[test]
    fn test_crypto_write_read_round_trip() {
        let original = (17..233).collect::<Vec<u8>>();
        let mut data = original.clone();
        let cursor = Cursor::new(&mut data);
        let mut dest = Vec::new();
        let key = util::generate_key();
        let iv = util::generate_iv();
        crypto_write(cursor, &mut dest, &key, &iv).unwrap();
        // crypto write should zero out the original sensitive data
        assert!(&data.iter().all(|x| *x == 0u8));
        data.clear();
        crypto_read(Cursor::new(dest), &mut data, &key, &iv).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_vault_data_conversion_round_trip() {
        let salt = generate_salt();
        let iv = generate_iv();
        let cipher_key = (1..17).collect::<Vec<u8>>();
        let vault_data = VaultData {
            salt,
            iv,
            cipher_master_key: cipher_key.clone(),
        };
        let serialized: Vec<u8> = vault_data.into();
        let rt: VaultData = serialized.try_into().unwrap();
        assert_eq!(rt.salt, salt);
        assert_eq!(rt.iv, iv);
        assert_eq!(rt.cipher_master_key, cipher_key);
    }

    #[test]
    fn test_header_conversion_round_trip() {
        let m_iv = generate_iv();
        let f_iv = generate_iv();
        let c_key = (1..17).collect::<Vec<u8>>();
        let header = FileHeader {
            master_iv: m_iv,
            iv: f_iv,
            cipher_key: c_key.clone(),
        };
        let serialized: Vec<u8> = header.into();
        let rt: FileHeader = serialized.try_into().unwrap();
        assert_eq!(rt.master_iv, m_iv);
        assert_eq!(rt.iv, f_iv);
        assert_eq!(rt.cipher_key, c_key);
    }

    #[test]
    fn test_generate_decrypt_header_round_trip() {
        let master_key = generate_key();
        let (header, file_key, file_iv) = generate_file_header(&master_key).unwrap();
        assert_eq!(header.iv, file_iv);
        let file_key_rt = decrypt_file_header(&header, &master_key).unwrap();
        assert_eq!(file_key, file_key_rt);
    }

    #[test]
    fn test_text_encryption_round_trip() {
        let master_key = generate_key();
        let text = "Hello World!";
        let encrypted = encrypt_text(text.into(), &master_key).unwrap();
        let decrypted = decrypt_text(&encrypted, &master_key).unwrap();
        assert_eq!(text, decrypted.unsecure());
    }

    #[test]
    fn test_text_to_file_round_trip() {
        let master_key = generate_key();
        let text = "Hello World!";
        let file = NamedTempFile::new().unwrap();
        encrypt_text_to_file(text.into(), file.path(), &master_key).unwrap();
        let decrypted = decrypt_text_from_file(file.path(), &master_key).unwrap();
        assert_eq!(text, decrypted.unsecure());
    }

    #[test]
    fn test_get_master_key() {
        let master_pw: SecureString = "password".into();
        let salt = generate_salt();
        let master_iv = generate_iv();
        let master_key = generate_key();
        let cipher_master_key = encrypt(
            Cipher::aes_256_cbc(),
            generate_key_from_password(&master_pw, &salt).unsecure(),
            Some(&master_iv),
            master_key.unsecure(),
        )
        .unwrap();
        let vault_data = VaultData {
            iv: master_iv,
            cipher_master_key,
            salt,
        };
        let key = get_master_key(master_pw, &vault_data).unwrap();
        assert_eq!(key, master_key);
    }
}
