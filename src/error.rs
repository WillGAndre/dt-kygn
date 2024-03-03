use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Secret Key provided has wrong length")]
    SecretKeyLenMismatch,
    #[error("Error converting from hex")]
    FromHexError(FromHexError),
    #[error("Invalid secret key")]
    InvalidSecretKey(secp256k1::Error),
}

impl From<FromHexError> for Error {
    fn from(value: FromHexError) -> Self {
        Self::FromHexError(value) 
    }
}

impl From<secp256k1::Error> for Error {
    fn from(value: secp256k1::Error) -> Self {
        Self::InvalidSecretKey(value) 
    }
}