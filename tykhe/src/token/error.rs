//! Result type and errors related to token stuff.

pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<Error> for Result<T> {
    fn from(value: Error) -> Self {
        Self::Err(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("token is not longer valid")]
    RejectedToken,
    #[error("same id in different payloads")]
    Collision,
    #[error("token regex did unmatch")]
    NotAToken,
    #[error("{0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("{0}")]
    Cache(#[from] crate::cache::Error),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}
