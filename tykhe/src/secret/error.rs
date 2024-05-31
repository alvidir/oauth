//! Result type and errors related to secrets stuff.

pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<Error> for Result<T> {
    fn from(value: Error) -> Self {
        Self::Err(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("secret not found")]
    NotFound,
    #[error("{0}")]
    Parse(#[from] std::string::ParseError),
    #[error("{0}")]
    Strum(#[from] strum::ParseError),
    #[error("{0}")]
    Uuid(#[from] uuid::Error),
    #[cfg(feature = "postgres")]
    #[error("{0}")]
    Sql(#[from] sqlx::error::Error),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}

impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }
}
