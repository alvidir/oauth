use super::{MailService, UserApplication, UserRepository};
use crate::cache::Cache;
use crate::multi_factor::service::MultiFactorService;
use crate::token::domain::{Claims, Token, TokenKind};
use crate::token::service::TokenService;
use crate::user::domain::{
    Credentials, CredentialsPrelude, Email, Password, PasswordHash, Salt, User,
};
use crate::user::error::{Error, Result};
use futures::join;

impl<U, S, T, F, M, C> UserApplication<U, S, T, F, M, C>
where
    U: UserRepository,
    T: TokenService,
    F: MultiFactorService,
    M: MailService,
    C: Cache,
{
    /// It temporally stores the given credentials in the cache and sends an email with the corresponding verification
    /// token to be passed as parameter to the signup_with_token method.
    #[instrument(skip(self, password))]
    pub async fn verify_credentials(&self, email: Email, password: Option<Password>) -> Result<()> {
        let Err(err) = self.user_repo.find_by_email(&email).await else {
            return Error::AlreadyExists.into();
        };

        if !err.not_found() {
            return Err(err);
        }

        let credentials_prelude = CredentialsPrelude {
            email,
            password: password
                .map(|password| {
                    let salt = Salt::with_length(self.hash_length)?;
                    PasswordHash::with_salt(&password, &salt)
                })
                .transpose()?,
        };

        let key = credentials_prelude.hash();
        let claims = self
            .token_srv
            .issue(TokenKind::Verification, &key.to_string())
            .await?;

        self.cache
            .save(
                &key.to_string(),
                &credentials_prelude,
                claims.payload().timeout(),
            )
            .await?;

        self.mail_srv
            .send_credentials_verification_email(&credentials_prelude.email, claims.token())?;

        Ok(())
    }

    /// Given a valid verification token, performs the signup of the corresponding user.
    /// The password field is mandatory if, and only if, no password was provided when verifying credentials. Otherwise
    /// that field will be ignored, since any cached value has priority.
    #[with_token(kind(Verification), no_user_id)]
    #[instrument(skip(self))]
    pub async fn signup_with_token(
        &self,
        token: Token,
        password: Option<Password>,
    ) -> Result<Claims> {
        let mut credentials_prelude = self
            .cache
            .find(claims.payload().subject())
            .await
            .map(CredentialsPrelude::from)?;

        if credentials_prelude.password.is_none() {
            credentials_prelude.password = password
                .map(|password| {
                    let salt = Salt::with_length(self.hash_length)?;
                    PasswordHash::with_salt(&password, &salt)
                })
                .transpose()?
        };

        let mut user = Credentials::try_from(credentials_prelude)?.into();

        let (revoke_token, clean_cache, signup) = join!(
            self.token_srv.revoke(&claims),
            self.cache.delete(claims.payload().subject()),
            self.signup(&mut user)
        );

        if let Err(error) = revoke_token {
            error!(error = error.to_string(), "revoking verification token");
        }

        if let Err(error) = clean_cache {
            error!(error = error.to_string(), "removing prelude from cache");
        }

        signup
    }

    /// Performs the signup for the given user.
    #[instrument(skip(self))]
    pub async fn signup(&self, user: &mut User) -> Result<Claims> {
        self.user_repo.create(user).await?;

        self.token_srv
            .issue(TokenKind::Session, &user.id.to_string())
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::{tests::InMemoryCache, Cache},
        token::{
            domain::{Claims, Payload, Token, TokenKind},
            service::tests::TokenServiceMock,
        },
        user::{
            application::tests::{new_user_application, MailServiceMock, UserRepositoryMock},
            domain::{
                Credentials, CredentialsPrelude, Email, Password, PasswordHash, Preferences, Salt,
                User, UserID,
            },
            error::Error,
        },
    };
    use std::time::Duration;
    use std::{str::FromStr, sync::Arc};

    #[tokio::test]
    async fn verify_credentials_when_user_already_exists() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|email: &Email| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::default(),
                preferences: Preferences::default(),
                credentials: Credentials {
                    email: email.clone(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
            })
        });

        let mut user_app = new_user_application();
        user_app.user_repo = Arc::new(user_repo);

        let email = Email::try_from("username@server.domain").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app.verify_credentials(email, Some(password)).await;
        assert!(
            matches!(result, Err(Error::AlreadyExists)),
            "got result = {:?}, want error = {:?}",
            result,
            Error::AlreadyExists
        )
    }

    #[tokio::test]
    async fn verify_credentials_when_repository_fails() {
        let user_app = new_user_application();

        let email = Email::try_from("username@server.domain").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app.verify_credentials(email, Some(password)).await;
        assert!(
            matches!(result, Err(Error::Debug)),
            "got result = {:?}, want error = {:?}",
            result,
            Error::Debug
        )
    }

    #[tokio::test]
    async fn verify_complete_credentials() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|_: &Email| Err(Error::NotFound));

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Verification, "unexpected token kind");

            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut mail_srv = MailServiceMock::default();
        mail_srv.send_credentials_verification_email_fn = Some(|email: &Email, token: &Token| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);
        user_app.mail_srv = Arc::new(mail_srv);

        let email = Email::try_from("username@server.domain").unwrap();

        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app.verify_credentials(email, Some(password)).await;
        assert!(matches!(result, Ok(_)), "{:?}", result,);

        assert!(
            user_app
                .cache
                .values
                .lock()
                .unwrap()
                .values()
                .into_iter()
                .map(ToString::to_string)
                .any(|value| {
                    let credentials = serde_json::from_str::<CredentialsPrelude>(&value).unwrap();
                    let actual_password = Password::try_from("abcABC123&".to_string()).unwrap();
                    credentials.email.as_ref() == "username@server.domain"
                        && credentials
                            .password
                            .map(|password| password.matches(&actual_password).unwrap())
                            .unwrap()
                }),
            "no credentials cached"
        );
    }

    #[tokio::test]
    async fn verify_uncomplete_credentials() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|_: &Email| Err(Error::NotFound));

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Verification, "unexpected token kind");

            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut mail_srv = MailServiceMock::default();
        mail_srv.send_credentials_verification_email_fn = Some(|email: &Email, token: &Token| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);
        user_app.mail_srv = Arc::new(mail_srv);

        let email = Email::try_from("username@server.domain").unwrap();

        let result = user_app.verify_credentials(email, None).await;
        assert!(matches!(result, Ok(_)), "{:?}", result,);

        assert!(
            user_app
                .cache
                .values
                .lock()
                .unwrap()
                .values()
                .into_iter()
                .map(ToString::to_string)
                .any(|value| {
                    let credentials = serde_json::from_str::<CredentialsPrelude>(&value).unwrap();
                    credentials.email.as_ref() == "username@server.domain"
                        && credentials.password.is_none()
                }),
            "no credentials cached"
        );
    }

    #[tokio::test]
    async fn signup_with_token_and_complete_credentials() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|user: &User| {
            assert_eq!(
                user.credentials.email.as_ref(),
                "username@server.domain",
                "unexpected email"
            );

            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");

            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        token_srv.revoke_fn = Some(|claims: &Claims| {
            assert_eq!(claims.token.as_ref(), "abc.abc.abc", "unexpected token");
            assert_eq!(
                claims.payload().kind(),
                TokenKind::Verification,
                "unexpected token kind"
            );
            assert_eq!(
                claims.payload().subject(),
                "signup",
                "unexpected token subject"
            );
            Ok(())
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: Some(PasswordHash::with_salt(&password, &salt).unwrap()),
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let token = user_app.signup_with_token(token, None).await.unwrap();

        assert_eq!(
            token.payload.kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );
    }

    #[tokio::test]
    async fn signup_with_token_and_uncomplete_credentials() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|user: &User| {
            assert_eq!(
                user.credentials.email.as_ref(),
                "username@server.domain",
                "unexpected email"
            );

            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");

            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        token_srv.revoke_fn = Some(|claims: &Claims| {
            assert_eq!(claims.token.as_ref(), "abc.abc.abc", "unexpected token");
            assert_eq!(
                claims.payload().kind(),
                TokenKind::Verification,
                "unexpected token kind"
            );
            assert_eq!(
                claims.payload().subject(),
                "signup",
                "unexpected token subject"
            );
            Ok(())
        });

        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: None,
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let token = user_app
            .signup_with_token(token, Some(password))
            .await
            .unwrap();

        assert_eq!(
            token.payload.kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );
    }

    #[tokio::test]
    async fn signup_with_token_when_reboke_fails() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|user: &User| {
            assert_eq!(
                user.credentials.email.as_ref(),
                "username@server.domain",
                "unexpected email"
            );

            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");

            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: Some(PasswordHash::with_salt(&password, &salt).unwrap()),
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let token = user_app.signup_with_token(token, None).await.unwrap();

        assert_eq!(
            token.payload.kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );
    }

    #[tokio::test]
    async fn signup_with_token_when_clean_cache_fails() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|user: &User| {
            assert_eq!(
                user.credentials.email.as_ref(),
                "username@server.domain",
                "unexpected email"
            );

            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");

            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        token_srv.revoke_fn = Some(|claims: &Claims| {
            assert_eq!(claims.token.as_ref(), "abc.abc.abc", "unexpected token");
            assert_eq!(
                claims.payload().kind(),
                TokenKind::Verification,
                "unexpected token kind"
            );
            assert_eq!(
                claims.payload().subject(),
                "signup",
                "unexpected token subject"
            );
            Ok(())
        });

        let mut cache = InMemoryCache::default();
        cache.delete_fn = Some(|key: &str| {
            assert_eq!(key, "signup", "unexpected item key");
            Err(crate::cache::Error::Debug)
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: Some(PasswordHash::with_salt(&password, &salt).unwrap()),
        };

        let mut user_app = new_user_application();
        user_app.cache = Arc::new(cache);

        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let token = user_app.signup_with_token(token, None).await.unwrap();

        assert_eq!(
            token.payload.kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );
    }

    #[tokio::test]
    async fn signup_with_token_and_uncomplete_credentials_without_password() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: None,
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let result = user_app.signup_with_token(token, None).await;

        assert!(
            matches!(result, Err(Error::Uncomplete)),
            "got result = {:?}, want error = {}",
            result,
            Error::Uncomplete
        );
    }

    #[tokio::test]
    async fn signup_with_token_when_invalid_token() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|_: TokenKind, _: &str| {
            assert!(false, "unexpected execution");
            Err(crate::token::error::Error::Debug)
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = CredentialsPrelude {
            email: Email::try_from("username@server.domain").unwrap(),
            password: Some(PasswordHash::with_salt(&password, &salt).unwrap()),
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("signup", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let result = user_app.signup_with_token(token, None).await;
        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }

    #[tokio::test]
    async fn signup_with_token_when_non_present_token() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("signup"),
            })
        });

        token_srv.issue_fn = Some(|_: TokenKind, _: &str| {
            assert!(false, "unexpected execution");
            Err(crate::token::error::Error::Debug)
        });

        let mut user_app = new_user_application();

        user_app.hash_length = 32;
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let result = user_app.signup_with_token(token, None).await;
        assert!(
            matches!(result, Err(Error::Cache(crate::cache::Error::NotFound))),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }

    #[tokio::test]
    async fn signup() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|user: &User| {
            assert_eq!(&user.id.to_string(), "bca4ec1c-da63-4d73-bad5-a82fc9853828");
            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");
            assert_eq!(
                sub, "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected token subject"
            );

            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let email = Email::try_from("username@server.domain").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = Credentials {
            email,
            password: PasswordHash::with_salt(&password, &salt).unwrap(),
        };

        let mut user = User {
            id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
            credentials,
            preferences: Preferences::default(),
        };

        let claims = user_app.signup(&mut user).await.unwrap();

        assert_eq!(
            claims.payload().kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );

        assert_eq!(
            claims.payload.subject(),
            user.id.to_string(),
            "expected user id in token subject"
        )
    }
}
