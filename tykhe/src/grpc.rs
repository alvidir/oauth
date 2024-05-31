//! gRPC utilities for managing request's headers.

use crate::{macros::on_error, multi_factor, session, token, user};
use tonic::{Request, Status};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Metadata(#[from] tonic::metadata::errors::ToStrError),
}

/// Given a gPRC request, returns the value of the provided header's key if any, otherwise an error
/// is returned.
pub fn header<T>(req: &Request<T>, header: &str) -> Result<Option<String>> {
    let Some(data) = req.metadata().get(header).map(|data| data.to_str()) else {
        return Ok(None);
    };

    data.map(|data| data.to_string())
        .map(Some)
        .map_err(on_error!(Error, "parsing header data to str"))
}

impl From<user::error::Error> for Status {
    fn from(error: user::error::Error) -> Status {
        Status::unknown("")
    }
}

impl From<token::error::Error> for Status {
    fn from(error: token::error::Error) -> Status {
        Status::unknown("")
    }
}

impl From<multi_factor::error::Error> for Status {
    fn from(error: multi_factor::error::Error) -> Status {
        Status::unknown("")
    }
}

impl From<session::error::Error> for Status {
    fn from(error: session::error::Error) -> Status {
        Status::unknown("")
    }
}

impl From<Error> for Status {
    fn from(error: Error) -> Status {
        Status::unknown("")
    }
}
