//! Result type and errors related to events stuff.

pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<Error> for Result<T> {
    fn from(value: Error) -> Self {
        Self::Err(value)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[cfg(feature = "postgres")]
    #[error("{0}")]
    Sql(#[from] sqlx::error::Error),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}
