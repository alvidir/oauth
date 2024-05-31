use crate::user::error::{Error, Result};
use ::regex::Regex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

const DOMAIN_SEPARATOR: char = '@';
const SUFIX_SEPARATOR: char = '+';

const PATTERN: &str = r"^[a-zA-Z0-9+._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$";
static REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(PATTERN).unwrap());

/// Represents an email with, or without, sufix.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email(String);

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Email {
    type Error = Error;

    /// Builds an [Email] from the given string if, and only if, the string matches the email's regex.
    fn try_from(value: &str) -> Result<Self> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for Email {
    type Error = Error;

    /// Builds an [Email] from the given string if, and only if, the string matches the email's regex.
    fn try_from(email: String) -> Result<Self> {
        REGEX
            .is_match(&email)
            .then_some(Self(email))
            .ok_or(Error::NotAnEmail)
    }
}

impl Email {
    /// Returns an email resulting from substracting the sufix from self, if any.
    pub fn actual_email(&self) -> Self {
        let email_parts: Vec<&str> = self.0.split(&[SUFIX_SEPARATOR, DOMAIN_SEPARATOR]).collect();

        if email_parts.len() == 3 {
            return Self(format!(
                "{}{}{}",
                email_parts[0], DOMAIN_SEPARATOR, email_parts[2],
            ));
        }

        self.clone()
    }

    /// Returns the username part from the email.
    pub fn username(&self) -> &str {
        self.0
            .split(&[SUFIX_SEPARATOR, DOMAIN_SEPARATOR])
            .next()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Email;
    use crate::user::error::Result;

    #[test]
    fn email_from_str() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            is_valid: bool,
        }

        vec![
            Test {
                name: "email without sufix",
                input: "username@server.domain",
                is_valid: true,
            },
            Test {
                name: "email with sufix",
                input: "username+sufix@server.domain",
                is_valid: true,
            },
            Test {
                name: "email with invalid characters",
                input: "username%@server.domain",
                is_valid: false,
            },
            Test {
                name: "email without usernamename",
                input: "@server.domain",
                is_valid: false,
            },
            Test {
                name: "email without servername",
                input: "username@.test",
                is_valid: false,
            },
            Test {
                name: "email without domain",
                input: "username@server",
                is_valid: false,
            },
            Test {
                name: "email with invalid domain",
                input: "username@server.d",
                is_valid: false,
            },
        ]
        .into_iter()
        .for_each(|test| {
            let result: Result<Email> = test.input.try_into();
            assert_eq!(result.is_ok(), test.is_valid, "{}", test.name);

            let Ok(email) = result else {
                return;
            };

            assert_eq!(email.as_ref(), test.input, "{}", test.name);
        })
    }

    #[test]
    fn actual_email_from_email() {
        struct Test<'a> {
            name: &'a str,
            input: Email,
            output: Email,
        }

        vec![
            Test {
                name: "email without sufix",
                input: Email("username@server.domain".to_string()),
                output: Email("username@server.domain".to_string()),
            },
            Test {
                name: "email with sufix",
                input: Email("username+sufix@server.domain".to_string()),
                output: Email("username@server.domain".to_string()),
            },
            Test {
                name: "email with empty sufix",
                input: Email("username+@server.domain".to_string()),
                output: Email("username@server.domain".to_string()),
            },
        ]
        .into_iter()
        .for_each(|test| {
            assert_eq!(
                Email::try_from(test.input).unwrap().actual_email(),
                test.output,
                "{}",
                test.name
            );
        })
    }

    #[test]
    fn username_from_email() {
        assert_eq!(
            Email::try_from("username@server.domain")
                .unwrap()
                .username(),
            "username"
        )
    }
}
