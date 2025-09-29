use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror;

#[cfg(windows)]
const ENDL: &str = "\r\n";
#[cfg(not(windows))]
const ENDL: &str = "\n";

#[derive(Debug, thiserror::Error)]
pub enum CreationError {
    #[error("Invalid JSON {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("IO Error {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    value: PathBuf,
    default: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum PathManagerError {
    #[error("Entry '{0}' not found")]
    EntryNotFound(String),
    #[error("Entry '{0}' already exists")]
    EntryExists(String),
    #[error("Empty name")]
    EmptyName,
    #[error("file system entry not found or no permission")]
    InvalidPath,
}

/// Holds named file system entries.
pub struct PathManager {
    entries: HashMap<String, PathBuf>,
    default: Option<String>,
}

impl PathManager {
    /// Creates an instance from a deserialized dictionary.
    /// # Parameters
    /// * `entries`: entries to manage
    pub fn new(entries: HashMap<String, Entry>) -> PathManager {
        let mut default = None;
        for (k, v) in &entries {
            if v.default {
                default = Some(k.clone());
            }
        }

        PathManager {
            entries: entries
                .into_iter()
                .map(|item| (item.0, item.1.value))
                .collect(),
            default,
        }
    }

    /// Creates an instance from a JSON string.
    /// # Parameters
    /// * `json`: JSON string
    /// # Returns
    /// * `PathManager`: instance
    /// # Errors
    /// * `CreationError`: if the JSON string is invalid
    pub fn from_json(json: &str) -> Result<PathManager, CreationError> {
        let entries: HashMap<String, Entry> = serde_json::from_str(json)?;
        Ok(PathManager::new(entries))
    }

    /// Saves the instance to a JSON file.
    /// # Parameters
    /// * `path`: path to save to
    /// # Errors
    /// * `CreationError`: if the file cannot be written
    pub fn save(&self, path: &str) -> Result<(), CreationError> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer(writer, &self.entries)?;
        Ok(())
    }

    /// Loads an instance from a JSON file.
    /// # Parameters
    /// * `path`: path to load from
    /// # Returns
    /// * `PathManager`: instance
    /// # Errors
    /// * `CreationError`: if the file cannot be read or is invalid
    pub fn load(path: &Path) -> Result<Self, CreationError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let entries: HashMap<String, Entry> = serde_json::from_reader(reader)?;
        Ok(PathManager::new(entries))
    }

    /// Returns a string with all entries.
    /// # Parameters
    /// * `show_val`: if true, the values are shown
    /// # Returns
    /// * `String`: string with all entries
    pub fn list_entries(&self, show_val: bool) -> String {
        let mut entries = String::new();
        for (k, v) in &self.entries {
            let default = self.default.as_ref().map_or_else(|| false, |d| k == d);
            let s = format!("{}{}", if default { "*" } else { "" }, k);
            if show_val {
                entries.push_str(&format!("{s} => {}{ENDL}", v.to_string_lossy()));
            } else {
                entries.push_str(&format!("{s}{ENDL}"));
            }
        }
        entries
    }

    /// Returns the default entry.
    /// # Returns
    /// The default entry or nothing if no default entry exits.
    pub fn get_default(&self) -> Option<&Path> {
        self.entries.get(self.default.as_ref()?).map(|v| v.as_path())
    }

    /// Returns the entry with the given name.
    /// # Parameters
    /// * `key`: name of the entry
    /// # Returns
    /// The entry or nothing if no entry with the given name exists.
    pub fn get(&self, key: &str) -> Option<&Path> {
        self.entries.get(key).map(|v| v.as_path())
    }

    /// Sets the default entry.
    /// # Parameters
    /// * `key`: name of the entry
    /// # Errors
    /// * `EntryManagerError`: if the entry does not exist
    pub fn set_default(&mut self, key: &str) -> Result<(), PathManagerError> {
        self.get(key)
            .ok_or(PathManagerError::EntryNotFound(key.to_string()))?;
        self.default = Some(key.to_string());
        Ok(())
    }

    /// Clears the default entry.
    pub fn clear_default(&mut self) {
        self.default = None;
    }

    /// Adds a new entry.
    /// # Parameters
    /// * `key`: name of the entry
    /// * `value`: path to the entry
    /// * `default`: if true, the entry is set as default
    /// # Errors
    /// * `EntryManagerError`: if the entry already exists or the path does not exist
    pub fn add(&mut self, key: String, value: PathBuf, default: bool) -> Result<(), PathManagerError> {
        if key.is_empty() {
            return Err(PathManagerError::EmptyName);
        }

        if self.get(&key).is_some() {
            return Err(PathManagerError::EntryExists(key.to_string()));
        }

        if !value.exists() {
            return Err(PathManagerError::InvalidPath);
        }

        self.entries.insert(key.clone(), value);
        self.default = Some(key);
        Ok(())
    }

    /// Removes an entry.
    /// # Parameters
    /// * `key`: name of the entry
    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
        if self.default.is_some() && self.default.as_ref().unwrap() == key {
            self.default = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn generate_data() -> HashMap<String, Entry> {
        let mut entries = HashMap::new();
        entries.insert(
            "test0".to_string(),
            Entry {
                value: PathBuf::from("value test0"),
                default: false,
            },
        );
        entries.insert(
            "test1".to_string(),
            Entry {
                value: PathBuf::from("value test1"),
                default: true,
            },
        );
        entries.insert(
            "test2".to_string(),
            Entry {
                value: PathBuf::from("value test2"),
                default: false,
            },
        );
        entries.insert(
            "test3".to_string(),
            Entry {
                value: PathBuf::from("value test3"),
                default: false,
            },
        );
        entries
    }

    #[test]
    fn test_new() {
        let pm = PathManager::new(generate_data());
        assert_eq!(pm.entries.len(), 4);
        assert_eq!(pm.default.unwrap(), "test1".to_string());
    }

    #[test]
    fn test_from_json() {
        let json = serde_json::to_string(&generate_data()).unwrap();
        let pm = PathManager::from_json(&json).unwrap();
        assert_eq!(pm.entries.len(), 4);
        assert_eq!(pm.default.unwrap(), "test1".to_string());
    }

    #[test]
    fn test_load() {
        let file = NamedTempFile::new().unwrap();
        let data = generate_data();
        serde_json::to_writer(&file, &data).unwrap();
        let pm = PathManager::load(file.path()).unwrap();
        assert_eq!(pm.entries.len(), 4);
        assert_eq!(pm.default.unwrap(), "test1".to_string());
    }

    #[test]
    fn test_get() {
        let pm = PathManager::new(generate_data());
        assert_eq!(pm.get("test0").unwrap().to_string_lossy(), "value test0");
        assert_eq!(pm.get("test1").unwrap().to_string_lossy(), "value test1");
        assert_eq!(pm.get("test2").unwrap().to_string_lossy(), "value test2");
        assert_eq!(pm.get("test3").unwrap().to_string_lossy(), "value test3");
        assert!(pm.get("gnaaa").is_none());
    }

    #[test]
    fn test_default() {
        let mut pm = PathManager::new(generate_data());
        assert_eq!(pm.get_default().unwrap(), Path::new("value test1"));
        pm.set_default("test2").unwrap();
        assert_eq!(pm.get_default().unwrap(), Path::new("value test2"));
        assert!(pm.set_default("asft44").is_err());
        pm.clear_default();
        assert!(pm.get_default().is_none());

    }

    #[test]
    fn test_remove() {
        let mut pm = PathManager::new(generate_data());
        assert_eq!(pm.entries.len(), 4);
        pm.remove("asdfasd");
        assert_eq!(pm.entries.len(), 4);
        pm.remove("test3");
        assert_eq!(pm.entries.len(), 3);
        assert!(pm.get("test3").is_none());
        assert_eq!(pm.get_default().unwrap(), Path::new("value test1"));
        pm.remove("test1");
        assert_eq!(pm.entries.len(), 2);
        assert!(pm.get("test1").is_none());
        assert!(pm.get_default().is_none());
    }
}
