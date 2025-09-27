use openssl::error::ErrorStack;
use std::fmt::{Display, Formatter};

#[derive(thiserror::Error, Debug)]
pub struct CryptoError(ErrorStack);

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.errors().len() == 0 {
            return write!(f, "Unknown SSL error");
        }

        let err = self.0.errors().first().unwrap();
        write!(
            f,
            "Cryptographic error: OpenSSL code: {:X}{}",
            err.code(),
            err.reason()
                .and_then(|r| Some(format!(" ({})", r)))
                .unwrap_or_default()
        )
    }
}

impl From<ErrorStack> for CryptoError {
    fn from(value: ErrorStack) -> Self {
        Self(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum InvalidHeader {
    #[error("Invalid header: expected {expected}, found {found}")]
    Format {
        expected: &'static str,
        found: String,
    },
    #[error("Invalid header: Io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum MpwError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    Cryptography(#[from] CryptoError),
    #[error(transparent)]
    InvalidHeader(#[from] InvalidHeader),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Invalid key length: {expected} vs {found} bytes")]
    InvalidKeyLength { expected: usize, found: usize },
    #[error("Invalid utf8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, MpwError>;

impl<T> From<InvalidHeader> for Result<T> {
    fn from(value: InvalidHeader) -> Self {
        Err(value.into())
    }
}

impl<T> From<MpwError> for Result<T> {
    fn from(value: MpwError) -> Self {
        Err(value)
    }
}

impl From<ErrorStack> for MpwError {
    fn from(value: ErrorStack) -> Self {
        Self::Cryptography(value.into())
    }
}
