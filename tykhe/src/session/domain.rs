use super::error::{Error, Result};
use crate::user::domain::Email;

/// Represents the identity of any user.
#[derive(Debug, PartialEq, Eq)]
pub enum Identity {
    Email(Email),
    Nick(String),
}

impl TryFrom<String> for Identity {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        match Email::try_from(value.as_str()) {
            Ok(email) => Ok(Identity::Email(email)),
            Err(error) if error.not_an_email() => Ok(Identity::Nick(value)),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::session::domain::Identity;

    #[test]
    fn identity_from_string() {
        struct Test<'a> {
            name: &'a str,
            input: &'a str,
            output: Identity,
        }

        vec![
            Test {
                name: "from email string",
                input: "username+sufix@server.domain",
                output: Identity::Email("username+sufix@server.domain".try_into().unwrap()),
            },
            Test {
                name: "from arbitrary string",
                input: "nickname δ中Δ",
                output: Identity::Nick("nickname δ中Δ".to_string()),
            },
        ]
        .into_iter()
        .for_each(|test| {
            let ident = Identity::try_from(test.input.to_string()).unwrap();
            assert_eq!(ident, test.output, "{}", test.name)
        })
    }
}
