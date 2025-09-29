use std::io::Write;
use crate::cryptography;
use crate::event::MessageEvent;
use crate::path_manager::{CreationError, PathManager};
use std::path::PathBuf;
use secure_string::SecureString;
use thiserror;
use openssl::rand::rand_bytes;
use crate::error::{MpwError};
use crate::vault::VaultError::VaultFileNotFound;

const VLT_EXTENSION: &'static str = ".vlt";
const PW_PATH: &'static str = "Passwords";
const VAULT_FILE: &'static str = constcat::concat!("Vault", VLT_EXTENSION);
const PW_EXTENSION: &'static str = "pwEnc";
const LOGIN_EXTENSION: &'static str = "lgEnc";
const FILE_EXTENSION: &'static str = "enc";
const FILE_LIST: &'static str = constcat::concat!("EncryptedFiles", VLT_EXTENSION);
const CONFIG_FILE: &'static str = constcat::concat!("config", VLT_EXTENSION);

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("Vault directory not found: {0}")]
    VaultDirNotFound(String),
    #[error("Vault file not found: {0}")]
    VaultFileNotFound(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    CoreError(#[from] MpwError),
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Password '{0}' not found")]
    PasswordNotFound(String),
    #[error("Password name '{0}' contains invalid characters")]
    InvalidPwName(String),
    #[error("'{0}' already exists")]
    AlreadyExists(String),
}

type VaultResult<T> = Result<T, VaultError>;

impl<T> From<VaultError> for VaultResult<T> {
    fn from(e: VaultError) -> Self {
        Err(e)
    }
}

fn assert_valid_name(pw_name: &str) -> Result<(), VaultError> {
    if pw_name.is_empty() || pw_name.contains("/")  || pw_name.contains(r"\") {
        return VaultError::InvalidPwName(pw_name.to_string()).into();
    }

    Ok(())
}

pub fn random_password(len: u32, forbidden_chars: &str) -> SecureString {
    let chars = ('!'..='~').filter(|c| !forbidden_chars.contains(*c)).collect::<Vec<char>>();
    let mut idx = vec![0u8; len as usize];
    rand_bytes(&mut idx).unwrap();
    idx.into_iter().map(|i| chars[i as usize % chars.len()]).collect::<String>().into()
}

pub struct Vault {
    working_dir: PathBuf,
    master_key: Option<cryptography::AesKey>,
    file_list: PathManager,
    pub warn: MessageEvent,
}

impl Vault {
    pub fn load(working_dir: PathBuf) -> VaultResult<Vault> {
        if !working_dir.is_dir() {
            return VaultError::VaultDirNotFound(
                working_dir.to_string_lossy().to_string(),
            ).into();
        }

        let file_list = working_dir.join(FILE_LIST);
        let files = match PathManager::load(&file_list) {
            Ok(f) => f,
            Err(e) => match e {
                CreationError::InvalidJson(_) => {
                    std::fs::File::create(file_list)?;
                    PathManager::new([].into())
                }
                CreationError::IoError(io) => {
                    if io.kind() == std::io::ErrorKind::NotFound {
                        std::fs::File::create(file_list)?;
                    } else {
                        return VaultError::IoError(io).into();
                    }

                    PathManager::new([].into())
                }
            },
        };

        Ok(Vault {
            working_dir,
            master_key: None,
            file_list: files,
            warn: MessageEvent::new(),
        })
    }

    pub fn new(working_dir: PathBuf, master_pw: SecureString) -> VaultResult<Vault> {
        if !working_dir.is_dir() {
            return VaultError::VaultDirNotFound(
                working_dir.to_string_lossy().to_string(),
            ).into();
        }

        let file_list = working_dir.join(FILE_LIST);
        let vault_file = working_dir.join(VAULT_FILE);
        std::fs::File::create(file_list)?;
        let mut v_fd = std::fs::File::create(vault_file)?;
        let (vault_data, _) = cryptography::generate_vault_data(master_pw)?;
        let vault_data: Vec<u8> = vault_data.into();
        v_fd.write_all(&vault_data)?;
        Self::load(working_dir)
    }

    pub fn is_locked(&self) -> bool {
        self.master_key.is_none()
    }

    pub fn unlock(&mut self, master_pw: SecureString) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Ok(());
        }

        let vlt_file = self.working_dir.join(VAULT_FILE);
        if !vlt_file.exists() {
            return VaultFileNotFound(vlt_file.to_string_lossy().to_string()).into();
        }

        let vd_stream = std::fs::File::open(vlt_file)?;
        let vault_data = cryptography::VaultData::load(vd_stream)?;
        self.master_key = Some(cryptography::get_master_key(master_pw, &vault_data)?);
        Ok(())
    }

    pub fn retrieve_password(&self, pw_name: &str) -> Result<(SecureString, Option<String>), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        let pw_path = self.working_dir.join(PW_PATH).join(pw_name).with_extension(PW_EXTENSION);
        let login_path = self.working_dir.join(PW_PATH).join(pw_name).with_extension(LOGIN_EXTENSION);
        if !pw_path.exists() {
            return VaultError::PasswordNotFound(pw_name.to_string()).into();
        }

        let pw = cryptography::decrypt_text_from_file(&pw_path, &self.master_key.as_ref().unwrap())?;
        let login = if login_path.exists() {
            Some(cryptography::decrypt_text_from_file(&login_path, &self.master_key.as_ref().unwrap())?.into_unsecure())
        } else {
            None
        };

        Ok((pw, login))
    }

    pub fn write_password(&self, pw_name: &str, pw: SecureString, login: Option<&str>, overwrite: bool) -> Result<(), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        assert_valid_name(pw_name)?;
        let pw_path = self.working_dir.join(PW_PATH).join(pw_name).with_extension(PW_EXTENSION);
        if pw_path.exists() && !overwrite {
            return VaultError::AlreadyExists(pw_name.to_string()).into();
        }

        if !pw_path.exists() && overwrite {
            return VaultError::PasswordNotFound(pw_name.to_string()).into();
        }

        if pw != "".into() {
            cryptography::encrypt_text_to_file(pw, &pw_path, &self.master_key.as_ref().unwrap())?;
        }
        if let Some(login) = login && login != "" {
            let login_path = self.working_dir.join(PW_PATH).join(pw_name).with_extension(LOGIN_EXTENSION);
            cryptography::encrypt_text_to_file(login.into(), &login_path, &self.master_key.as_ref().unwrap())?;
        }

        Ok(())
    }

    pub fn change_master_password(&mut self, master_pw: SecureString) -> Result<(), VaultError> {
        let vlt_file_path = self.working_dir.join(VAULT_FILE);
        let (vlt_data, master_key) = cryptography::generate_vault_data(master_pw)?;
        self.master_key = Some(master_key);
        let mut vtl_fd = std::fs::File::create(vlt_file_path)?;
        let vlt_data: Vec<u8> = vlt_data.into();
        vtl_fd.write_all(&vlt_data)?;
        Ok(())

    }

    pub fn list_passwords(&self) -> Result<Vec<String>, VaultError> {
        let mut ret = vec![];
        for entry in std::fs::read_dir(self.working_dir.join(PW_PATH))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path.file_stem().is_some()
                && path.extension().unwrap_or_default() == PW_EXTENSION
            {
                ret.push(path.file_stem().unwrap().to_string_lossy().to_string());
            }
        }

        Ok(ret)
    }
}
