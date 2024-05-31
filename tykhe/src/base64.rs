//! Criptography utilities for the validation and generation of JWTs as well as RSA encription and decription.

use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine,
};

pub const B64_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

/// Encodes an slice of u8 into a b64 string.
pub fn encode(v: &[u8]) -> String {
    B64_ENGINE.encode(v)
}
