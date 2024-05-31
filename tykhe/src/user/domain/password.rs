use crate::{
    base64,
    macros::on_error,
    user::error::{Error, Result},
};
use argon2::Argon2;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Represents the hash and salt of a [Password].
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHash {
    pub(crate) hash: String,
    pub(crate) salt: Salt,
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        &self.hash
    }
}

impl PasswordHash {
    /// Builds a new password from the given value and salt
    pub fn with_salt(password: &Password, salt: &Salt) -> Result<Self> {
        let mut buffer = vec![0_u8; salt.as_str().len()];

        Argon2::default()
            .hash_password_into(password.as_ref(), salt.as_ref(), &mut buffer)
            .map(|_| Self {
                hash: base64::encode(&buffer),
                salt: salt.clone(),
            })
            .map_err(on_error!(Error, "salting and hashing password"))
    }

    /// Returns true if, and only if, the given password matches with self.
    pub fn matches(&self, other: &Password) -> Result<bool> {
        PasswordHash::with_salt(other, &self.salt).map(|subject| &subject == self)
    }

    /// Returns the salt of the hash.
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
}

/// Represents a password.
#[derive(Debug, Clone)]
pub struct Password(String);

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<String> for Password {
    type Error = Error;

    /// Builds a [Password] from the given string if, and only if, the string matches the
    /// password's regex.
    fn try_from(password: String) -> Result<Self> {
        if password.len() < 8 {
            return Err(Error::NotAPassword);
        }

        // lowercase, uppercase , number , special
        let mut aggregate = [false; 4];
        password.chars().for_each(|c| {
            aggregate[0] |= c.is_lowercase();
            aggregate[1] |= c.is_uppercase();
            aggregate[2] |= c.is_numeric();
            aggregate[3] |= !(c.is_lowercase() || c.is_uppercase() || c.is_numeric());
        });

        if aggregate.contains(&false) {
            return Err(Error::NotAPassword);
        }

        Ok(Password(password))
    }
}

/// Represents the salt of a password.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Salt(String);

impl AsRef<str> for Salt {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<String> for Salt {
    type Error = Error;

    fn try_from(salt: String) -> Result<Self> {
        if salt.is_empty() || salt.chars().any(|c| !c.is_alphanumeric()) {
            return Err(Error::NotASalt);
        }

        Ok(Self(salt))
    }
}

impl Salt {
    /// Builds a new [Salt] with the given length for any length greater than 0. Otherwise returns [Error::NotASalt].
    pub fn with_length(len: usize) -> Result<Self> {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect::<String>()
            .try_into()
    }

    /// Returns a reference to the literal value of self.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Password, PasswordHash, Salt};
    use crate::user::error::Error;

    #[test]
    fn password_hash_matches() {
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(128).unwrap();
        let hash = PasswordHash::with_salt(&password, &salt).unwrap();

        assert_eq!(
            hash.salt(),
            &salt,
            "hash does not contains the correct salt"
        );

        assert!(
            hash.matches(&password).unwrap(),
            "comparing password with its own hash"
        );

        let fake_password = Password::try_from("abcABC1234&".to_string()).unwrap();
        assert!(
            !hash.matches(&fake_password).unwrap(),
            "comparing password with wrong hash"
        );
    }

    #[test]
    fn password_from_str() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            is_valid: bool,
        }

        vec![
            Test {
                name: "valid password",
                input: "abcABC123&",
                is_valid: true,
            },
            Test {
                name: "password without special characters",
                input: "abcABC123",
                is_valid: false,
            },
            Test {
                name: "password without uppercase characters",
                input: "abcabc123&",
                is_valid: false,
            },
            Test {
                name: "password without lowercase characters",
                input: "ABCABC123&",
                is_valid: false,
            },
            Test {
                name: "password with less than 8 characters",
                input: "aB1&",
                is_valid: false,
            },
            Test {
                name: "empty password",
                input: "",
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Password::try_from(test.input.to_string());
            if test.is_valid {
                let password = result.unwrap();
                assert_eq!(password.as_ref(), test.input.as_bytes(), "{0}", test.name);
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotAPassword)),
                    "{}",
                    test.name
                );
            }
        })
    }

    #[test]
    fn salt_from_str() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            is_valid: bool,
        }

        vec![
            Test {
                name: "alphanumeric salt",
                input: "abc123",
                is_valid: true,
            },
            Test {
                name: "non alphanumeric salt",
                input: "abc123&",
                is_valid: false,
            },
            Test {
                name: "empty salt",
                input: "",
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Salt::try_from(test.input.to_string());
            if test.is_valid {
                let salt = result.unwrap();
                assert_eq!(salt.as_str(), test.input, "{0}", test.name);
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotASalt)),
                    "{}",
                    test.name
                );
            }
        })
    }

    #[test]
    fn salt_with_length() {
        struct Test<'a> {
            name: &'a str,
            len: usize,
            is_valid: bool,
        }

        vec![
            Test {
                name: "with no length",
                len: 0,
                is_valid: false,
            },
            Test {
                name: "with length 10",
                len: 10,
                is_valid: true,
            },
            Test {
                name: "with length 100",
                len: 100,
                is_valid: true,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Salt::with_length(test.len);
            if test.is_valid {
                let salt = result.unwrap();
                assert_eq!(salt.as_str().len(), test.len, "{}", test.name);

                assert!(
                    Salt::try_from(salt.as_str().to_string()).is_ok(),
                    "{}",
                    test.name
                );
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotASalt)),
                    "{}",
                    test.name
                );
            }
        })
    }

    #[test]
    fn password_hash_with_salt_when_argon_fails() {
        let password = Password("".to_string());
        let salt = Salt("".to_string());

        let result = PasswordHash::with_salt(&password, &salt);
        assert!(
            matches!(result, Err(Error::Argon(_))),
            "got result = {:?}, want argon error",
            result,
        );
    }
}
