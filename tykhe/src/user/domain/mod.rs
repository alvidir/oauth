mod email;
pub use email::*;

mod password;
pub use password::*;

mod credentials;
pub use credentials::*;

mod event;
pub use event::*;

use super::error::Result;
use crate::multi_factor::domain::MultiFactorMethod;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use uuid::Uuid;

/// Represents the universal unique id of a user.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct UserID(
    #[serde(
        serialize_with = "uuid_as_string",
        deserialize_with = "uuid_from_string"
    )]
    Uuid,
);

fn uuid_as_string<S>(uuid: &Uuid, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

fn uuid_from_string<'de, D>(deserializer: D) -> std::result::Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let uuid = String::deserialize(deserializer)?;
    Uuid::from_str(&uuid)
        .map_err(|err| err.to_string())
        .map_err(Error::custom)
}

impl FromStr for UserID {
    type Err = uuid::Error;

    fn from_str(uuid: &str) -> std::result::Result<Self, Self::Err> {
        Uuid::from_str(uuid).map(Self)
    }
}

impl ToString for UserID {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for UserID {
    fn default() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Represents the preferences of a user.
#[derive(Debug, Default)]
pub struct Preferences {
    pub multi_factor: Option<MultiFactorMethod>,
}

/// Represents a user.
#[derive(Debug)]
pub struct User {
    pub id: UserID,
    pub credentials: Credentials,
    pub preferences: Preferences,
}

impl From<Credentials> for User {
    fn from(credentials: Credentials) -> Self {
        Self {
            id: UserID::default(),
            credentials,
            preferences: Preferences::default(),
        }
    }
}

impl User {
    /// Returns true if, and only if, the given password matches with the one from self.
    pub fn password_matches(&self, other: &Password) -> Result<bool> {
        self.credentials.password.matches(other)
    }
}

#[cfg(test)]
mod tests {
    use super::UserID;
    use crate::user::domain::{Credentials, Email, Password, PasswordHash, Salt, User};

    #[test]
    fn user_password_matches() {
        let email = Email::try_from("username@server.domain").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(128).unwrap();
        let hash = PasswordHash::with_salt(&password, &salt).unwrap();
        let credentials = Credentials {
            email,
            password: hash,
        };
        let user = User::from(credentials);

        assert!(
            user.password_matches(&password).unwrap(),
            "comparing password with its own hash"
        );

        let fake_password = Password::try_from("abcABC1234&".to_string()).unwrap();
        assert!(
            !user.password_matches(&fake_password).unwrap(),
            "comparing password with wrong hash"
        );
    }

    #[test]
    fn user_id_serde() {
        let want = UserID::default();
        let json = serde_json::to_string(&want).unwrap();
        let got: UserID = serde_json::from_str(&json).unwrap();

        assert_eq!(got, want, "serde ends up with different values");
    }
}
