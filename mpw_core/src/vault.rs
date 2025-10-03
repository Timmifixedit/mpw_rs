use crate::cryptography;
use crate::error::MpwError;
use crate::event::MessageEvent;
use crate::path_manager::{CreationError, PathManager, PathManagerError};
use openssl::rand::rand_bytes;
use secure_string::SecureString;
use std::fmt::{Display, Formatter};
use std::io::{Seek, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use thiserror;

const VLT_EXTENSION: &'static str = "vlt";
const PW_PATH: &'static str = "Passwords";
const VAULT_FILE: &'static str = constcat::concat!("Vault", ".", VLT_EXTENSION);
const PW_EXTENSION: &'static str = "pwEnc";
const LOGIN_EXTENSION: &'static str = "lgEnc";
const FILE_EXTENSION: &'static str = "enc";
const FILE_LIST: &'static str = constcat::concat!("EncryptedFiles", ".", VLT_EXTENSION);
const CONFIG_FILE: &'static str = constcat::concat!("config", ".", VLT_EXTENSION);

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
    #[error("Invalid parameter '{0}'")]
    InvalidParameter(String),
    #[error("{item} is a protected item within the vault directory {vault_dir}")]
    VaultItem { item: String, vault_dir: String },
    #[error("{0} is a protected item that already belongs to a vault.")]
    ProtectedItem(String),
    #[error("{0} is already encrypted")]
    AlreadyEncrypted(String),
    #[error("{0} is not encrypted")]
    NotEncrypted(String),
    #[error(transparent)]
    PathManagerError(#[from] PathManagerError),
}

#[derive(thiserror::Error, Debug)]
pub struct VaultErrorStack {
    pub errors: Vec<VaultError>,
}

impl Display for VaultErrorStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for e in &self.errors {
            writeln!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl From<VaultError> for VaultErrorStack {
    fn from(e: VaultError) -> Self {
        Self { errors: vec![e] }
    }
}

impl VaultErrorStack {
    pub fn new() -> Self {
        Self { errors: vec![] }
    }

    pub fn append_if_error<T>(&mut self, expr: Result<T, Self>) -> Result<T, ()> {
        match expr {
            Ok(vale) => Ok(vale),
            Err(e) => {
                for e in e.errors {
                    self.errors.push(e);
                }
                Err(())
            }
        }
    }

    pub fn add_if_error<T, E>(&mut self, expr: Result<T, E>) -> Result<T, ()>
    where
        E: Into<VaultError>,
    {
        match expr {
            Ok(vale) => Ok(vale),
            Err(e) => {
                self.errors.push(e.into());
                Err(())
            }
        }
    }

    pub fn empty(&self) -> bool {
        self.errors.is_empty()
    }
}

type VaultResult<T> = Result<T, VaultError>;

impl<T> From<VaultError> for VaultResult<T> {
    fn from(e: VaultError) -> Self {
        Err(e)
    }
}

fn assert_valid_name(pw_name: &str) -> Result<(), VaultError> {
    if pw_name.is_empty() || pw_name.contains("/") || pw_name.contains(r"\") {
        return VaultError::InvalidPwName(pw_name.to_string()).into();
    }

    Ok(())
}

pub fn random_password(
    len: NonZeroU32,
    forbidden_chars: Option<&str>,
) -> VaultResult<SecureString> {
    let chars = ('!'..='~')
        .filter(|c| forbidden_chars.map_or_else(|| true, |f| !f.contains(*c)))
        .collect::<Vec<char>>();
    if chars.is_empty() {
        return VaultError::InvalidParameter(
            "No character options left for random password".to_string(),
        )
        .into();
    }
    let mut idx = vec![0u8; len.get() as usize];
    rand_bytes(&mut idx).unwrap();
    Ok(idx
        .into_iter()
        .map(|i| chars[i as usize % chars.len()])
        .collect::<String>()
        .into())
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
            return VaultError::VaultDirNotFound(working_dir.to_string_lossy().to_string()).into();
        }

        if !working_dir.join(VAULT_FILE).exists() {
            return VaultError::VaultFileNotFound(
                working_dir.join(VAULT_FILE).to_string_lossy().to_string(),
            )
            .into();
        }

        if !working_dir.join(PW_PATH).is_dir() {
            std::fs::create_dir_all(working_dir.join(PW_PATH))?;
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
            return VaultError::VaultDirNotFound(working_dir.to_string_lossy().to_string()).into();
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
            return VaultError::VaultFileNotFound(vlt_file.to_string_lossy().to_string()).into();
        }

        let vd_stream = std::fs::File::open(vlt_file)?;
        let vault_data = cryptography::VaultData::load(vd_stream)?;
        self.master_key = Some(cryptography::get_master_key(master_pw, &vault_data)?);
        Ok(())
    }

    pub fn retrieve_password(
        &self,
        pw_name: &str,
    ) -> Result<(SecureString, Option<String>), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }
        let (pw_path, login_path) = self.get_pw_by_name(pw_name)?;
        let pw =
            cryptography::decrypt_text_from_file(&pw_path, &self.master_key.as_ref().unwrap())?;
        let login = if let Some(login_path) = login_path {
            Some(
                cryptography::decrypt_text_from_file(
                    &login_path,
                    &self.master_key.as_ref().unwrap(),
                )?
                .into_unsecure(),
            )
        } else {
            None
        };

        Ok((pw, login))
    }

    pub fn write_password(
        &self,
        pw_name: &str,
        pw: SecureString,
        login: Option<&str>,
        overwrite: bool,
    ) -> Result<(), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        let (pw_path, login_path) = self.pw_name_to_path(pw_name);
        assert_valid_name(pw_name)?;
        if pw_path.exists() && !overwrite {
            return VaultError::AlreadyExists(pw_name.to_string()).into();
        }

        if !pw_path.exists() && overwrite {
            return VaultError::PasswordNotFound(pw_name.to_string()).into();
        }

        if pw != "".into() {
            cryptography::encrypt_text_to_file(pw, &pw_path, &self.master_key.as_ref().unwrap())?;
        }
        if let Some(login) = login
            && login != ""
        {
            cryptography::encrypt_text_to_file(
                login.into(),
                &login_path,
                &self.master_key.as_ref().unwrap(),
            )?;
        }

        Ok(())
    }

    pub fn change_master_password(&mut self, master_pw: SecureString) -> Result<(), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        let vlt_file_path = self.working_dir.join(VAULT_FILE);
        let vlt_data = cryptography::generate_vault_data_with_key(
            master_pw,
            self.master_key.as_ref().unwrap(),
        )?;
        let mut vtl_fd = std::fs::File::create(vlt_file_path)?;
        let vlt_data: Vec<u8> = vlt_data.into();
        vtl_fd.write_all(&vlt_data)?;
        Ok(())
    }

    pub fn list_passwords(&self, search: Option<&str>) -> Result<Vec<String>, VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        let mut ret = vec![];
        for entry in std::fs::read_dir(self.working_dir.join(PW_PATH))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path.file_stem().is_some()
                && path.extension().unwrap_or_default() == PW_EXTENSION
                && path
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .contains(search.unwrap_or_default())
            {
                ret.push(path.file_stem().unwrap().to_string_lossy().to_string());
            }
        }

        Ok(ret)
    }

    pub fn list_files(&self, show_path: bool, search_string: Option<&str>) -> Vec<String> {
        self.file_list.list_entries(show_path, search_string)
    }

    fn pw_name_to_path(&self, name: &str) -> (PathBuf, PathBuf) {
        (
            self.working_dir
                .join(PW_PATH)
                .join(name)
                .with_extension(PW_EXTENSION),
            self.working_dir
                .join(PW_PATH)
                .join(name)
                .with_extension(LOGIN_EXTENSION),
        )
    }

    fn get_pw_by_name(&self, pw_name: &str) -> Result<(PathBuf, Option<PathBuf>), VaultError> {
        let (pw_path, login_path) = self.pw_name_to_path(pw_name);
        if !pw_path.exists() {
            return VaultError::PasswordNotFound(pw_name.to_string()).into();
        }

        Ok((
            pw_path,
            if login_path.exists() {
                Some(login_path)
            } else {
                None
            },
        ))
    }

    pub fn delete_password(&self, pw_name: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        let (pw_path, login_path) = self.get_pw_by_name(pw_name)?;
        std::fs::remove_file(pw_path)?;
        if let Some(login_path) = login_path {
            std::fs::remove_file(login_path)?;
        }
        Ok(())
    }

    fn verify_file_path(&self, file_path: &Path, expect_dir: bool) -> Result<(), VaultError> {
        use std::io::Error as IO;
        use std::io::ErrorKind as EK;
        let path_str = file_path.to_string_lossy();
        if !expect_dir && file_path.is_dir() {
            return Err(IO::new(EK::IsADirectory, format!("{path_str} is a directory")).into());
        }

        if expect_dir && file_path.is_file() {
            return Err(IO::new(EK::NotADirectory, format!("{path_str} is a file")).into());
        }

        if !file_path.exists() {
            return Err(IO::new(EK::NotFound, format!("Item '{path_str}' not found")).into());
        }

        if file_path.starts_with(&self.working_dir) {
            return VaultError::VaultItem {
                item: path_str.to_string(),
                vault_dir: self.working_dir.to_string_lossy().to_string(),
            }
            .into();
        }

        if file_path.extension().is_some_and(|e| {
            [PW_EXTENSION, VLT_EXTENSION]
                .iter()
                .any(|c| *c == e.to_string_lossy().as_ref())
        }) {
            return VaultError::ProtectedItem(path_str.to_string()).into();
        }

        Ok(())
    }

    pub fn encrypt_file(&self, file_path: &Path) -> Result<(), VaultError> {
        use std::io::Error as IO;
        use std::io::ErrorKind as EK;
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        self.verify_file_path(file_path, false)?;
        if file_path
            .extension()
            .is_some_and(|e| e.to_string_lossy() == FILE_EXTENSION)
        {
            return VaultError::AlreadyEncrypted(file_path.to_string_lossy().to_string()).into();
        }

        let dest_path = file_path.with_extension(
            file_path
                .extension()
                .map_or_else(|| "".into(), |e| e.to_string_lossy().to_string() + ".")
                + FILE_EXTENSION,
        );
        if dest_path.exists() {
            return Err(IO::new(
                EK::AlreadyExists,
                format!(
                    "Encryption target file already exists: {}",
                    dest_path.to_string_lossy()
                ),
            )
            .into());
        }

        let mut encrypted = std::fs::File::create(dest_path)?;
        let src = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(file_path)?;
        let (header, key, iv) =
            cryptography::generate_file_header(self.master_key.as_ref().unwrap())?;
        let header: Vec<u8> = header.into();
        encrypted.write_all(header.as_slice())?;
        cryptography::crypto_write(src, &mut encrypted, &key, &iv)?;
        std::fs::remove_file(file_path)?;
        Ok(())
    }

    pub fn decrypt_file(&self, file_path: &Path) -> Result<(), VaultError> {
        use std::io::Error as IO;
        use std::io::ErrorKind as EK;
        if self.is_locked() {
            return VaultError::VaultLocked.into();
        }

        self.verify_file_path(file_path, false)?;
        if file_path
            .extension()
            .is_some_and(|e| e.to_string_lossy() != FILE_EXTENSION)
        {
            return VaultError::NotEncrypted(file_path.to_string_lossy().to_string()).into();
        }

        let dest_path = file_path.with_extension("");
        if dest_path.exists() {
            return Err(IO::new(
                EK::AlreadyExists,
                format!(
                    "Decryption target file already exists: {}",
                    dest_path.to_string_lossy()
                ),
            )
            .into());
        }

        let mut src = std::fs::File::open(file_path)?;
        let header = cryptography::FileHeader::load(&src)?;
        let file_key =
            cryptography::decrypt_file_header(&header, &self.master_key.as_ref().unwrap())?;
        src.seek(std::io::SeekFrom::Start(header.data_offset() as u64))?;
        let mut dest = std::fs::File::create(dest_path)?;
        cryptography::crypto_read(src, &mut dest, &file_key, &header.iv)?;
        std::fs::remove_file(file_path)?;
        Ok(())
    }

    fn recursive_operation<F>(&self, dir_path: &Path, op: &F) -> Result<(), VaultErrorStack>
    where
        F: Fn(&Path) -> Result<(), VaultError>,
    {
        if self.is_locked() {
            return Err(VaultError::VaultLocked.into());
        }

        self.verify_file_path(dir_path, true)?;
        let mut errors = VaultErrorStack::new();
        for entry in std::fs::read_dir(dir_path).map_err(|e| -> VaultError { e.into() })? {
            let body = || -> Result<(), ()> {
                let entry = errors.add_if_error(entry)?;
                let path = entry.path();
                if path.is_dir() {
                    errors.append_if_error(self.recursive_operation(&path, op))?;
                } else {
                    errors.add_if_error(op(&path))?;
                }

                Ok(())
            };

            let _ = body();
        }

        if !errors.empty() { Err(errors) } else { Ok(()) }
    }

    pub fn encrypt_directory(&self, dir_path: &Path) -> Result<(), VaultErrorStack> {
        self.recursive_operation(dir_path, &|p| self.encrypt_file(p))
    }

    pub fn decrypt_directory(&self, dir_path: &Path) -> Result<(), VaultErrorStack> {
        self.recursive_operation(dir_path, &|p| self.decrypt_file(p))
    }

    pub fn add_fs_entry(&mut self, path: PathBuf, name: String) -> Result<(), VaultError> {
        self.file_list.add(name, path, false).map_err(|e| e.into())
    }

    pub fn rename_fs_entry(&mut self, old_name: &str, new_name: String) -> Result<(), VaultError> {
        let entry = self
            .file_list
            .get(old_name)
            .ok_or(VaultError::PathManagerError(
                PathManagerError::EntryNotFound(old_name.to_string()),
            ))?
            .to_owned();

        self.file_list.remove(old_name);
        self.file_list.add(new_name, entry, false)?;
        Ok(())
    }

    pub fn rename_password(&mut self, old_name: &str, new_name: &str) -> Result<(), VaultError> {
        let (pw_path, login_path) = self.get_pw_by_name(old_name)?;
        if self.get_pw_by_name(new_name).is_ok() {
            return VaultError::AlreadyExists(new_name.to_string()).into();
        }

        let (pw_new, login_new) = self.pw_name_to_path(new_name);
        std::fs::rename(pw_path, pw_new)?;
        if let Some(login_path) = login_path {
            std::fs::rename(login_path, login_new)?;
        }

        Ok(())
    }

    pub fn write_file_list(&self) -> Result<(), VaultError> {
        let serialized = self.file_list.to_json().expect("Serialization failed");
        let mut file = std::fs::File::create(self.working_dir.join(FILE_LIST))?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    pub fn remove_fs_entry(&mut self, name: &str) -> Result<(), VaultErrorStack> {
        let entry = self
            .file_list
            .get(name)
            .ok_or(VaultError::PathManagerError(
                PathManagerError::EntryNotFound(name.to_string()),
            ))?
            .to_owned();
        self.file_list.remove(name);
        if entry.is_dir() {
            self.decrypt_directory(&entry)?;
        } else {
            self.decrypt_file(&entry)?;
        }

        Ok(())
    }

    pub fn encrypt_by_name(&self, name: &str) -> Result<(), VaultErrorStack> {
        let entry = self
            .file_list
            .get(name)
            .ok_or(VaultError::PathManagerError(
                PathManagerError::EntryNotFound(name.to_string()),
            ))?;
        if entry.is_dir() {
            self.encrypt_directory(entry)?;
        } else {
            self.encrypt_file(entry)?;
        }

        Ok(())
    }

    pub fn decrypt_by_name(&self, name: &str) -> Result<(), VaultErrorStack> {
        let entry = self
            .file_list
            .get(name)
            .ok_or(VaultError::PathManagerError(
                PathManagerError::EntryNotFound(name.to_string()),
            ))?;
        if entry.is_dir() {
            self.decrypt_directory(entry)?;
        } else {
            self.decrypt_file(entry)?;
        }

        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), VaultErrorStack> {
        if self.is_locked() {
            return Ok(());
        }

        let mut err = VaultErrorStack::new();
        for (name, _) in self.file_list.iter() {
            let _ = err.append_if_error(self.encrypt_by_name(name));
        }

        self.master_key = None;
        if !err.empty() { Err(err) } else { Ok(()) }
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Err(e) = self.write_file_list() {
            eprintln!("Error writing file list: {}", e);
        }
    }
}
