use crate::user::domain::{User, UserID};

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, strum_macros::EnumString, strum_macros::AsRefStr,
)]
#[strum(serialize_all = "lowercase")]
pub enum SecretKind {
    Otp,
    Salt,
}

/// Represent some sensitive data that cannot be updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub owner: UserID,
    pub kind: SecretKind,
    pub(crate) data: Vec<u8>, // read-only data
}

impl Secret {
    /// Returns a brand new secret with the given data.
    pub fn new(kind: SecretKind, owner: &User, data: &[u8]) -> Self {
        Secret {
            owner: owner.id,
            kind,
            data: data.to_vec(),
        }
    }

    /// Returns the Salt secret corresponding to the given user.
    pub fn new_salt(owner: &User) -> Self {
        Secret::new(
            SecretKind::Salt,
            owner,
            owner.credentials.password.salt().as_ref(),
        )
    }

    /// Returns an immutable reference to the secret's data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
