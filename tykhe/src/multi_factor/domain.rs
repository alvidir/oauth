use super::error::{Error, Result};
use rand::{distributions::Uniform, Rng};
use std::str::FromStr;

/// Represents the multi factor authentication method to use.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MultiFactorMethod {
    /// A third-party application is used to get the TOTP.
    TpApp,
    /// The OTP is sent via email.
    Email,
    /// Any other method.
    Other(String),
}

impl ToString for MultiFactorMethod {
    fn to_string(&self) -> String {
        match self {
            MultiFactorMethod::TpApp => "tp_app".to_string(),
            MultiFactorMethod::Email => "email".to_string(),
            MultiFactorMethod::Other(other) => other.clone(),
        }
    }
}

impl FromStr for MultiFactorMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "tp_app" => Ok(Self::TpApp),
            "email" => Ok(Self::Email),
            other => Ok(Self::Other(other.to_string())),
        }
    }
}

/// Represents a one time password.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Otp(String);

impl AsRef<str> for Otp {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Otp {
    type Error = Error;

    /// Builds a [OTP] from the given string if, and only if, the string matches the
    /// otp's regex.
    fn try_from(otp: String) -> Result<Self> {
        if otp.is_empty() || otp.chars().any(|c| !c.is_numeric()) {
            return Err(Error::NotAOneTimePassword);
        }

        Ok(Self(otp))
    }
}

impl Otp {
    /// Builds a new [Otp] with the given length for any length greater than 0. Otherwise returns [Error::NotAOneTimePassword].
    pub fn with_length(len: usize) -> Result<Self> {
        rand::thread_rng()
            .sample_iter(Uniform::new_inclusive(0, 9))
            .take(len)
            .map(|digit| digit.to_string())
            .collect::<String>()
            .try_into()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::multi_factor::{
        domain::{MultiFactorMethod, Otp},
        error::Error,
    };

    #[test]
    fn display_multi_factor_method() {
        struct Test<'a> {
            name: &'a str,
            output: &'a str,
            input: MultiFactorMethod,
        }

        vec![
            Test {
                name: "third party application method",
                output: "tp_app",
                input: MultiFactorMethod::TpApp,
            },
            Test {
                name: "email method",
                output: "email",
                input: MultiFactorMethod::Email,
            },
            Test {
                name: "an arbitrary name",
                output: "arbitrary method",
                input: MultiFactorMethod::Other("arbitrary method".to_string()),
            },
        ]
        .into_iter()
        .for_each(|test| assert_eq!(test.input.to_string(), test.output, "{}", test.name))
    }

    #[test]
    fn multi_factor_method_from_str() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            output: MultiFactorMethod,
        }

        vec![
            Test {
                name: "third party application method",
                input: "tp_app",
                output: MultiFactorMethod::TpApp,
            },
            Test {
                name: "email method",
                input: "email",
                output: MultiFactorMethod::Email,
            },
            Test {
                name: "an arbitrary name",
                input: "arbitrary method",
                output: MultiFactorMethod::Other("arbitrary method".to_string()),
            },
        ]
        .into_iter()
        .for_each(|test| {
            let got = MultiFactorMethod::from_str(test.input).unwrap();
            assert_eq!(got, test.output, "{}", test.name)
        })
    }

    #[test]
    fn otp_from_str() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            is_valid: bool,
        }

        vec![
            Test {
                name: "numeric otp",
                input: "1234",
                is_valid: true,
            },
            Test {
                name: "non numeric otp",
                input: "abc123&",
                is_valid: false,
            },
            Test {
                name: "empty otp",
                input: "",
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Otp::try_from(test.input.to_string());
            if test.is_valid {
                let otp = result.unwrap();
                assert_eq!(otp.as_ref(), test.input, "{0}", test.name);
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotAOneTimePassword)),
                    "{}",
                    test.name
                );
            }
        })
    }

    #[test]
    fn otp_with_length() {
        struct Test<'a> {
            name: &'a str,
            len: usize,
            is_valid: bool,
        }

        vec![
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
            Test {
                name: "with no length",
                len: 0,
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result = Otp::with_length(test.len);
            if test.is_valid {
                let otp = result.unwrap();
                assert_eq!(otp.as_ref().len(), test.len, "{}", test.name);

                assert!(
                    Otp::try_from(otp.as_ref().to_string()).is_ok(),
                    "{}",
                    test.name
                );
            } else {
                assert!(
                    matches!(result.err(), Some(Error::NotAOneTimePassword)),
                    "{}",
                    test.name
                );
            }
        })
    }
}
