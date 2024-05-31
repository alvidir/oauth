use crate::{session, token};
use axum::http::StatusCode;

impl From<session::error::Error> for StatusCode {
    fn from(value: session::error::Error) -> Self {
        todo!()
    }
}

impl From<token::error::Error> for StatusCode {
    fn from(value: token::error::Error) -> Self {
        todo!()
    }
}
