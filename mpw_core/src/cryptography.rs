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
pub type AesIV = [u8; AES_IV_LEN.value];
pub type Salt = [u8; HMAC_SALT_LEN.value];
pub type AesKey = SecureArray<u8, { AES_KEY_LEN.value }>;

// Structures

/// Represents the contents of the main vault file, i.e. the master key.
///
/// # Members
/// * iv: AES initialization vector
/// * cipher_master_key: Cipher text master key
/// * salt: Salt for password derive function
pub struct VaultData {
    pub iv: AesIV,
    pub cipher_master_key: Vec<u8>,
    pub salt: Salt,
}

/// Represents the header of an arbitrary encrypted file.
///
/// # Members
/// * master_iv: AES initialization vector used in the encryption of this file's key
/// * iv: AES initialization vector used in the encryption of this file's contents
/// * cipher_key: Cipher text file key used to encrypt this file's contents
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
        VaultData::load(Cursor::new(value))
    }
}

impl TryFrom<Vec<u8>> for VaultData {
    type Error = MpwError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VaultData::load(Cursor::new(value))
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
        FileHeader::load(Cursor::new(value))
    }
}

impl TryFrom<Vec<u8>> for FileHeader {
    type Error = MpwError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        FileHeader::load(Cursor::new(value))
    }
}

// Structure method implementations
impl VaultData {
    /// Constructs a new `VaultData` instance by parsing the provided data stream.
    ///
    /// This function reads and validates the binary data from the provided input stream
    /// to create a `VaultData` instance. It verifies the integrity of the data by
    /// checking the lengths of the initialization vector (IV) and the salt against
    /// their expected sizes. If these validations fail or an I/O error occurs, an error
    /// is returned.
    ///
    /// # Type Parameters
    /// - `T`: A type that implements both the `Read` and `Seek` traits, used to
    ///        read and navigate through the input data stream.
    ///
    /// # Arguments
    /// - `data`: A mutable instance of a type that implements `Read + Seek`. This stream
    ///           should contain the serialized vault data in the appropriate format.
    ///
    /// # Returns
    /// * Returns `VaultData` if the data parsing and validations are successful.
    ///
    /// # Errors
    /// - `error::InvalidHeader::Format`: If the length of the IV or salt from the input
    ///    data does not match the expected length.
    /// - `error::InvalidHeader::Io`: If there are issues reading from the input stream.
    ///
    /// # Expected Input Format (endian is specified by `USE_LITTLE_ENDIAN.value`)
    /// The input stream is expected to conform to the following binary format:
    /// 1. 4 bytes encoding the length of the IV
    /// 2. 4 bytes encoding the length of the cipher key.
    /// 3. Initialization vector (IV): Fixed length, as defined by `AES_IV_LEN.value`.
    /// 4. Cipher key: Variable length, specified in the header.
    /// 5. Salt length: 4 bytes.
    /// 6. Salt: Fixed length, as defined by `HMAC_SALT_LEN.value`.
    ///
    /// # Example
    /// ```rust
    /// use std::io::Cursor;
    /// use mpw_core::cryptography::VaultData;
    ///
    /// let fake_data = Cursor::new(vec![/* Serialized binary data */]);
    /// match VaultData::load(fake_data) {
    ///     Ok(vault_data) => println!("VaultData initialized successfully!"),
    ///     Err(e) => eprintln!("Failed to initialize VaultData: {:?}", e),
    /// }
    /// ```
    ///
    /// # See Also
    /// - `VaultData`: The struct this function initializes.
    /// - `error::InvalidHeader`: Possible error variants returned by this function.
    pub fn load<T: Read + Seek>(mut data: T) -> error::Result<VaultData> {
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
    /// Constructs a new `FileHeader` by reading and parsing data from an input source that
    /// implements the `Read` and `Seek` traits.
    ///
    /// # Type Parameters
    /// - `T`: A type that implements both the `Read` and `Seek` traits, used to
    ///        read and navigate through the input data stream.
    ///
    /// # Parameters
    /// - `data`: An input source that contains the binary data needed for parsing the file header.
    ///
    /// # Returns
    /// - `FileHeader` if the data is successfully read and conforms to the expected structure.
    ///
    /// # Errors
    /// Returns an `error::InvalidHeader` in the following cases:
    /// - If the `master_iv_len` or `iv_len` in the header does not match the expected `AES_IV_LEN.value`.
    /// - If the IO operation fails while reading data from the input.
    ///
    /// # File Header Structure
    /// The method reads and validates the following fields from the provided input source:
    /// - A 12-byte header containing:
    ///   - Bytes [0..4]: `master_iv_len` (length of the master IV).
    ///   - Bytes [4..8]: `iv_len` (length of the IV).
    ///   - Bytes [8..12]: `key_len` (length of the cipher key).
    /// - `master_iv`: A sequence of bytes of length `AES_IV_LEN.value` starting at byte 12.
    /// - `iv`: A sequence of bytes of length `AES_IV_LEN.value`, following the `master_iv`.
    /// - `cipher_key`: A sequence of bytes of length `key_len`, following the IV.
    ///
    /// # Validations
    /// - `master_iv_len` and `iv_len` must be equal to `AES_IV_LEN.value`.
    /// - Proper handling of IO errors and slice conversion is applied.
    ///
    /// # Example
    /// ```
    /// use std::io::Cursor;
    /// use mpw_core::cryptography::FileHeader;
    ///
    /// let cursor = Cursor::new(vec![/* Serialized binary data */]);
    /// if let Ok(header) = FileHeader::load(cursor) {
    ///     // ...
    /// }
    /// ```
    pub fn load<T: Read + Seek>(mut data: T) -> error::Result<FileHeader> {
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

pub mod util {
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


/// Creates a new main vault data structure and encrypts it using the master password.
/// # Parameters
/// * `master_pw`: The master password to use for the vault instance
///
/// # Returns:
/// * New VaultData instance and the master key
///
/// # Errors:
/// * Encryption errors
///
/// # Examples:
/// ```
/// use mpw_core::cryptography::VaultData;
/// let password = "secret password".into();
/// let vault_data = VaultData::new(password);
/// ```
pub fn generate_vault_data(master_pw: SecureString) -> error::Result<(VaultData, AesKey)> {
    let master_key = util::generate_key();
    let salt = util::generate_salt();
    let iv = util::generate_iv();
    let pw_key = generate_key_from_password(&master_pw, &salt);
    let cipher_master_key = encrypt(
        Cipher::aes_256_cbc(),
        pw_key.unsecure(),
        Some(&iv),
        master_key.unsecure(),
    )?;
    Ok((VaultData {
        iv,
        cipher_master_key,
        salt,
    }, master_key))
}

/// Generates an AES encryption key derived from a given password and salt using the PBKDF2 algorithm.
///
/// # Parameters
/// * `password` - A reference to a `SecureString` containing the password from which the key will be derived.
/// * `salt` - A reference to a `Salt` used in the key derivation process.
///
/// # Returns
/// * An `AesKey` that represents the derived key suitable for encryption or decryption operations.
///
/// # Example
/// ```
/// use mpw_core::cryptography::generate_key_from_password;
/// use mpw_core::cryptography::util::generate_salt;
/// let pw = "secure password".into();
/// let salt = generate_salt();
/// let key = generate_key_from_password(&pw, &salt);
/// ```
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

/// Retrieves the vault master key by decrypting the encrypted key stored in the provided vault data.
///
/// # Arguments
///
/// * `master_pw` - A secure string containing the master password.
/// * `vault_data` - A reference to the `VaultData` structure.
///
/// # Returns
///
/// This function returns a `Result` containing:
/// * A ready-to-use `AesKey` upon successful decryption
///
/// # Errors
///
/// This function may return the following errors:
/// * `MpwError::InvalidKeyLength` - If the decrypted key has not the expected length.
/// * `MpwError::WrongPassword` - If the master password provided is incorrect.
/// * `MpwError::Cryptography` - For other decryption-specific errors encountered during the process.
///
/// # Example
/// ```
/// use mpw_core::cryptography::{get_master_key, VaultData};
/// # use mpw_core::cryptography::util::{generate_iv, generate_salt};
///
/// let master_pw = "your_master_password".into();
/// # let salt = generate_salt();
/// # let iv = generate_iv();
/// # let cipher_master_key = vec![0u8; 48];
/// let vault_data = VaultData{iv, cipher_master_key, salt};
/// if let Ok(master_key) = get_master_key(master_pw, &vault_data) {
///     //...
/// }
/// ```
pub fn get_master_key(master_pw: SecureString, vault_data: &VaultData) -> error::Result<AesKey> {
    let key = generate_key_from_password(&master_pw, &vault_data.salt);
    match decrypt(
        Cipher::aes_256_cbc(),
        key.unsecure(),
        Some(&vault_data.iv),
        &vault_data.cipher_master_key,
    ) {
        Ok(key) => Ok(SecureArray::new(key.try_into().map_err(|e: Vec<u8>| {
            MpwError::InvalidKeyLength {
                expected: AES_KEY_LEN.value,
                found: e.len(),
            }
        })?)),
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

/// Decrypts and returns a secure string from an encrypted file.
///
/// This function reads the entire content of the file located at the given `path`,
/// and attempts to decrypt it using the provided AES key (`master_key`).
/// The decrypted output is returned as a `SecureString`.
///
/// # Arguments
/// * `path` - A reference to a `Path` which specifies the location of the encrypted file.
/// * `master_key` - A reference to an `AesKey` used to decrypt the file's content.
///
/// # Returns
/// If successful, this function returns a `SecureString` containing the decrypted text.
///
/// # Errors
/// This function will return an error in the following situations:
/// - If the file at the specified `path` cannot be read.
/// - If the file's content cannot be decrypted using the provided `master_key`.
/// - UTF8 error is returned if the decrypted text contains invalid UTF8 characters.
///
/// # Note
/// This method is only meant to be used for decrypting small text files as all the file's content
/// is loaded into memory. For larger files of arbitrary content, use `crypto_read` instead.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// use mpw_core::cryptography::{decrypt_text_from_file, AesKey};
/// # use mpw_core::cryptography::util::generate_key;
///
/// let path = Path::new("encrypted_file.enc");
/// # let master_key = generate_key();
/// if let Ok(text) = decrypt_text_from_file(&path, &master_key) {
///     println!("Decrypted text: {}", text.unsecure());
/// }
/// ```
pub fn decrypt_text_from_file(path: &Path, master_key: &AesKey) -> error::Result<SecureString> {
    let cipher_data = io::read_all(path, Start(0))?;
    decrypt_text(&cipher_data, master_key)
}

/// Encrypts the given text and writes it to a specified file.
///
/// # Parameters
/// * `text` - A `SecureString` containing the plaintext data that needs to be encrypted.
/// * `path` - A reference to a `Path` that specifies the file location to write the encrypted data.
/// * `master_key` - A reference to an `AesKey` used for encryption.
///
/// # Returns
/// * `Ok(())` - If the operation completes successfully, this function returns without error.
///
/// # Errors
/// This function may fail for the following reasons:
/// * If the encryption process fails.
/// * If the file cannot be created at the specified path.
/// * If an error occurs while writing the encrypted data to the file.
///
/// # Examples
/// ```
/// use mpw_core::cryptography::encrypt_text_to_file;
/// use mpw_core::cryptography::util::generate_key;
/// use std::path::Path;
///
/// let text = "Sensitive information".into();
/// let path = Path::new("encrypted_data.enc");
/// # let file = tempfile::NamedTempFile::new().unwrap();
/// # let path = file.path();
/// let master_key = generate_key();
/// encrypt_text_to_file(text, &path, &master_key).unwrap();
/// ```
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

/// Generates the header for encrypted files.
/// # Parameters
/// * `master_key`: Master key used for encryption
/// # Returns
/// * The generated header
/// * an AES key that has to be used for encrypting the actual contents and
/// * the corresponding IV
/// # Errors
/// * Cryptographic errors returned by OpenSSL
/// # Example
/// ```
/// use mpw_core::cryptography::generate_file_header;
/// use mpw_core::cryptography::util::generate_key;
/// let master_key = generate_key();
/// let (header, key, iv) = generate_file_header(&master_key).unwrap();
/// ```
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

/// Recovers the master key from the encrypted file header.
/// # Parameters
/// * `header`: The file header containing the encrypted key used for file encryption
/// * `master_kex`: The master AES key
/// # Returns
/// * The AES key that can be used to decrypt the file contents
/// # Errors
/// * Cryptographic errors returned by OpenSSL
/// # Example
/// ```
/// use mpw_core::cryptography::{generate_file_header, decrypt_file_header};
/// use mpw_core::cryptography::util::generate_key;
/// let master_key = generate_key();
/// let (header, key, iv) = generate_file_header(&master_key).unwrap();
/// let recovered_key = decrypt_file_header(&header, &master_key).unwrap();
/// assert_eq!(key, recovered_key)
/// ```
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

/// Encrypts a given text unsing the provided key.
/// # Parameters
/// * `data`: The text to be encrypted
/// * `key`: The master key to be used for encryption of the file header
/// # Returns
/// * The encrypted text with its corresponding file header
/// # Errors
/// * Cryptographic errors returned by OpenSSL
/// # Example
/// ```
/// use mpw_core::cryptography::encrypt_text;
/// use mpw_core::cryptography::util::generate_key;
/// let text = "Sensitive text".into();
/// let master_key = generate_key();
/// let result = encrypt_text(text, &master_key).unwrap();
/// ```
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

/// Decrypts a given text using the provided master key.
/// # Parameters
/// * `data`: The text to be decrypted. The actual text is preceded by the file header.
/// * `key`: The master key to be used for decryption of the file header
/// # Returns
/// * The decrypted text
/// # Errors
/// * File header parsing errors
/// * Cryptographic errors returned by OpenSSL
/// * UTF8 error if the data cannot be represented as an UTF8 string
/// # Example
/// ```
/// use mpw_core::cryptography::{decrypt_text, encrypt_text};
/// use mpw_core::cryptography::util::generate_key;
/// let text = "Sensitive text".into();
/// let master_key = generate_key();
/// let result = encrypt_text(text, &master_key).unwrap();
/// let recovered = decrypt_text(&result, &master_key).unwrap();
/// assert_eq!("Sensitive text", recovered.unsecure());
///
/// ```
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

/// Transfers data from an unencrypted source stream to a destination stream while performing
/// encryption. The source will be zeroed out after the transfer.
/// # Type Parameters
/// * `Source`: The type of the source stream.
/// * `Dest`: The type of the destination stream.
/// # Parameters
/// * `source`: The source stream. The date may be unencrypted.
/// * `dest`: The destination stream. The encrypted data will be written to this stream.
/// * `key`: The encryption key.
/// * `iv`: The initialization vector.
/// # Errors
/// * Errors reported by OpenSSL
/// * IO errors
/// # Note
/// The source stream will be zeroed out.
/// # Example
/// ```
/// use std::io::Cursor;
/// use mpw_core::cryptography::crypto_write;
/// use mpw_core::cryptography::util::{generate_iv, generate_key};
/// let mut sensitive_data = (1..100).collect::<Vec<u8>>();
/// let mut destination = Vec::new();
/// let key = generate_key();
/// let iv = generate_iv();
/// crypto_write(Cursor::new(&mut sensitive_data), &mut destination, &key, &iv).unwrap();
/// assert!(sensitive_data.iter().all(|x| *x == 0u8));
/// ```
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

/// Transfers data from an encrypted source stream to a destination stream while performing
/// decryption.
/// # Type Parameters
/// * `Source`: The type of the source stream.
/// * `Dest`: The type of the destination stream.
/// # Parameters
/// * `source`: The source stream. The encrypted data will be read from this stream.
/// * `dest`: The destination stream. The decrypted data will be written to this stream.
/// * `key`: The decryption key.
/// * `iv`: The initialization vector.
/// # Errors
/// * Cryptographic errors reported by OpenSSL
/// * IO errors
/// # Example
/// ```
/// use std::io::Cursor;
/// use mpw_core::cryptography::{crypto_read, crypto_write};
/// use mpw_core::cryptography::util::{generate_iv, generate_key};
/// let mut sensitive_data = (1..100).collect::<Vec<u8>>();
/// let mut destination = Vec::new();
/// let key = generate_key();
/// let iv = generate_iv();
/// crypto_write(Cursor::new(&mut sensitive_data), &mut destination, &key, &iv).unwrap();
/// let mut recovered = Vec::new();
/// crypto_read(Cursor::new(destination), &mut recovered, &key, &iv).unwrap();
/// assert_eq!(recovered, (1..100).collect::<Vec<u8>>());
/// ```
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
