//! Result type and errors related to multi factor stuff.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("one time password regex did not match")]
    NotAOneTimePassword,
    #[error("multi factor method not found")]
    NotFound,
    #[error("one time password required")]
    Required,
    #[error("wrong one time password")]
    Invalid,
    #[error("the resource must be acknowledged")]
    Ack(String),
    #[error("{0}")]
    Secret(#[from] crate::secret::error::Error),
    #[error("{0}")]
    Cache(#[from] crate::cache::Error),
    #[error("{0}")]
    Oath(#[from] libreauth::oath::Error),
    #[error("{0}")]
    String(#[from] std::string::FromUtf8Error),
    #[cfg(feature = "smtp")]
    #[error("{0}")]
    Tera(#[from] tera::Error),
    #[cfg(feature = "smtp")]
    #[error("{0}")]
    Smtp(#[from] crate::smtp::Error),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}
