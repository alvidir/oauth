use super::{Email, PasswordHash};
use crate::user::error::Error;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

/// Represents a user credentials that may, or may not, be complete.
/// This struct is used to temporally store credentials that has not already been validated
#[derive(Debug, Hash, Serialize, Deserialize)]
pub struct CredentialsPrelude {
    pub password: Option<PasswordHash>,
    pub email: Email,
}

impl CredentialsPrelude {
    /// Returns the result of hashing self.
    pub fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        Hash::hash(self, &mut hasher);
        hasher.finish()
    }
}

/// Represents the credentials of a [User].
#[derive(Debug, Hash)]
pub struct Credentials {
    pub password: PasswordHash,
    pub email: Email,
}

impl TryFrom<CredentialsPrelude> for Credentials {
    type Error = Error;

    fn try_from(prelude: CredentialsPrelude) -> Result<Self, Self::Error> {
        let Some(password_hash) = prelude.password else {
            return Err(Error::Uncomplete);
        };

        Ok(Credentials {
            email: prelude.email,
            password: password_hash,
        })
    }
}
