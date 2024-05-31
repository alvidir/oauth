//! Result type and errors related to user stuff.

use crate::event;

pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<Error> for Result<T> {
    fn from(value: Error) -> Self {
        Self::Err(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("email regex did not match")]
    NotAnEmail,
    #[error("password regex did not match")]
    NotAPassword,
    #[error("salt is not alphanumeric")]
    NotASalt,
    #[error("wrong user credentials")]
    WrongCredentials,
    #[error("user not found")]
    NotFound,
    #[error("user already exists")]
    AlreadyExists,
    #[error("token is not of the correct kind")]
    WrongToken,
    #[error("forbidden")]
    Forbidden,
    #[error("some fields are missing")]
    Uncomplete,
    #[error("{0}")]
    Strum(#[from] strum::ParseError),
    #[error("{0}")]
    Salt(#[from] std::array::TryFromSliceError),
    #[cfg(feature = "grpc")]
    #[error("{0}")]
    Tonic(#[from] tonic::metadata::errors::InvalidMetadataValue),
    #[cfg(feature = "postgres")]
    #[error("{0}")]
    Sql(#[from] sqlx::error::Error),
    #[cfg(feature = "smtp")]
    #[error("{0}")]
    Tera(#[from] tera::Error),
    #[cfg(feature = "rabbitmq")]
    #[error("{0}")]
    Deadpool(#[from] deadpool_lapin::PoolError),
    #[cfg(feature = "rabbitmq")]
    #[error("{0}")]
    Lapin(#[from] lapin::Error),
    #[error("{0}")]
    Cache(#[from] crate::cache::Error),
    #[cfg(feature = "smtp")]
    #[error("{0}")]
    Smtp(#[from] crate::smtp::Error),
    #[error("{0}")]
    Token(#[from] crate::token::error::Error),
    #[error("{0}")]
    MultiFactor(#[from] crate::multi_factor::error::Error),
    #[error("{0}")]
    Secret(#[from] crate::secret::error::Error),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Uuid(#[from] uuid::Error),
    #[error("{0}")]
    Event(#[from] event::error::Error),
    #[error("{0}")]
    Argon(String),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}

impl From<argon2::Error> for Error {
    fn from(value: argon2::Error) -> Self {
        Self::Argon(value.to_string())
    }
}

impl Error {
    pub fn not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }

    pub fn not_an_email(&self) -> bool {
        matches!(self, Error::NotAnEmail)
    }
}
