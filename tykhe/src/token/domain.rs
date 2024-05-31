use super::error::{Error, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PATTERN: &str = r"^(?:[\w-]*\.){2}[\w-]*$";
static REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(PATTERN).unwrap());

/// Represents the kind of a token.
#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum TokenKind {
    Session,
    Verification,
    Reset,
}

/// Represents the payload of a JWT, containing the claims.
#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub jti: String,
    pub iss: String,
    pub sub: String,
    #[serde(
        serialize_with = "as_unix_timestamp",
        deserialize_with = "from_unix_timestamp"
    )]
    pub exp: SystemTime,
    #[serde(
        serialize_with = "as_unix_timestamp",
        deserialize_with = "from_unix_timestamp"
    )]
    pub nbf: SystemTime,
    #[serde(
        serialize_with = "as_unix_timestamp",
        deserialize_with = "from_unix_timestamp"
    )]
    pub iat: SystemTime,
    pub knd: TokenKind,
}

fn as_unix_timestamp<S>(
    timestamp: &SystemTime,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::Error;

    timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(|err| Error::custom(err.to_string()))
        .and_then(|timestamp| serializer.serialize_u64(timestamp.as_secs()))
}

fn from_unix_timestamp<'de, D>(deserializer: D) -> std::result::Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    u64::deserialize(deserializer)
        .map(Duration::from_secs)
        .and_then(|duration| {
            UNIX_EPOCH
                .checked_add(duration)
                .ok_or_else(|| Error::custom("cannot be represented as SystemTime".to_string()))
        })
}

impl Payload {
    /// Builds a new payload of the given kind and with the specified lifetime.
    pub fn new(token_kind: TokenKind, lifetime: Duration) -> Self {
        Payload {
            jti: Default::default(),
            iss: Default::default(),
            sub: Default::default(),
            exp: SystemTime::now() + lifetime,
            nbf: SystemTime::now(),
            iat: SystemTime::now(),
            knd: token_kind,
        }
    }

    pub fn with_subject(mut self, subject: &str) -> Self {
        self.sub = subject.to_string();
        self
    }

    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.iss = issuer.to_string();
        self
    }

    pub fn with_id(mut self, id: String) -> Self {
        self.jti = id;
        self
    }

    /// Returns the [Duration] from now for which self is valid.
    pub fn timeout(&self) -> Duration {
        self.exp
            .duration_since(SystemTime::now())
            .unwrap_or_default()
    }

    /// Returns the [Kind] field from self.
    pub fn kind(&self) -> TokenKind {
        self.knd.clone()
    }

    /// Returns the subject field (sub) from self.
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// Returns the result of hashing self.
    pub fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        Hash::hash(self, &mut hasher);
        hasher.finish()
    }
}

/// Represents a signed token.
#[derive(Debug)]
pub struct Token(String);

impl TryFrom<String> for Token {
    type Error = Error;

    fn try_from(token: String) -> Result<Self> {
        REGEX
            .is_match(&token)
            .then_some(Self(token))
            .ok_or(Error::NotAToken)
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Represents a token and its corresponding payload, containing the claims.
#[derive(Debug)]
pub struct Claims {
    pub token: Token,
    pub payload: Payload,
}

impl Claims {
    /// Returns the token with the corresponding claims.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// Returns the payload, containing the claims.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }
}

#[cfg(test)]
pub mod tests {
    use crate::token::{domain::Token, error::Error};

    use super::{Payload, TokenKind};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use strum::IntoEnumIterator;

    #[test]
    fn new_payload() {
        TokenKind::iter().for_each(|token_kind| {
            let timeout = Duration::from_secs(60);

            let before = SystemTime::now();
            let payload = Payload::new(token_kind.clone(), timeout);
            let after = SystemTime::now();

            assert!(
                payload.iat >= before && payload.iat <= after,
                "wrong issued at (iat) attribute"
            );

            assert!(
                payload.exp >= before + timeout,
                "wrong expiration (exp) attribute"
            );

            assert!(
                payload.exp <= after + timeout,
                "wrong expiration (exp) attribute"
            );

            assert_eq!(payload.kind(), token_kind, "wrong kind (knd) attribute");
        });
    }

    #[test]
    fn payload_timeout() {
        TokenKind::iter().for_each(|token_kind| {
            let timeout = Duration::from_secs(60);
            let payload = Payload::new(token_kind.clone(), timeout);

            let before = SystemTime::now();
            let timeout = SystemTime::UNIX_EPOCH + payload.timeout();
            let after = SystemTime::now();

            assert!(
                timeout <= SystemTime::UNIX_EPOCH + payload.exp.duration_since(before).unwrap(),
                "wrong payload timeout"
            );

            assert!(
                timeout >= SystemTime::UNIX_EPOCH + payload.exp.duration_since(after).unwrap(),
                "wrong payload timeout"
            );
        });
    }

    #[test]
    fn token_from_string() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            is_valid: bool,
        }

        vec![
            Test {
                name: "json web token format",
                input: "abc.123.x-_",
                is_valid: true,
            },
            Test {
                name: "invalid jwt format",
                input: "abc.1&3.-_",
                is_valid: false,
            },
            Test {
                name: "no format",
                input: "abc123",
                is_valid: false,
            },
            Test {
                name: "empty token",
                input: "",
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Token::try_from(test.input.to_string());
            if test.is_valid {
                let token = result.unwrap();
                assert_eq!(token.as_ref(), test.input, "{0}", test.name);
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotAToken)),
                    "{}",
                    test.name
                );
            }
        })
    }

    #[test]
    fn payload_serde() {
        let want = Payload {
            jti: "json web token id".to_string(),
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            exp: UNIX_EPOCH,
            nbf: UNIX_EPOCH,
            iat: UNIX_EPOCH,
            knd: TokenKind::Session,
        };

        let json = serde_json::to_string(&want).unwrap();
        let got: Payload = serde_json::from_str(&json).unwrap();

        assert_eq!(got, want, "serde ends up with different values");
    }
}
