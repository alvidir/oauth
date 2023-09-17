use super::{EventService, MailService, UserApplication, UserRepository};
use crate::cache::Cache;
use crate::mfa::service::MfaService;
use crate::token::domain::{Claims, Token, TokenKind};
use crate::token::service::TokenService;
use crate::user::domain::{Credentials, Email, Password, PasswordHash, Salt, User};
use crate::user::error::{Error, Result};

impl<U, S, T, F, M, B, C> UserApplication<U, S, T, F, M, B, C>
where
    U: UserRepository,
    T: TokenService,
    F: MfaService,
    M: MailService,
    B: EventService,
    C: Cache,
{
    /// Stores the given credentials in the cache and sends an email with the token to be
    /// passed as parameter to the signup_with_token method.
    #[instrument(skip(self, password))]
    pub async fn verify_credentials(&self, email: Email, password: Password) -> Result<()> {
        let Err(err) = self.user_repo.find_by_email(&email).await else {
            return Error::AlreadyExists.into();
        };

        if !err.not_found() {
            return Err(err);
        }

        let salt = Salt::with_length(self.hash_length)?;
        let credentials = Credentials {
            email,
            password: PasswordHash::with_salt(&password, &salt)?,
        };

        let key = credentials.hash();
        let claims = self
            .token_srv
            .issue(TokenKind::Verification, &key.to_string())
            .await?;

        self.cache
            .save(&key.to_string(), &credentials, claims.payload().timeout())
            .await?;

        self.mail_srv
            .send_credentials_verification_email(&credentials.email, claims.token())?;

        Ok(())
    }

    /// Given a valid verification token, performs the signup of the corresponding user.
    #[instrument(skip(self))]
    pub async fn signup_with_token(&self, token: Token) -> Result<Claims> {
        let claims = self.token_srv.claims(token).await?;

        if !claims.payload().kind().is_verification() {
            return Error::WrongToken.into();
        }

        let mut user = self
            .cache
            .find(claims.payload().subject())
            .await
            .map(Credentials::into)?;

        self.token_srv.revoke(&claims).await?;
        self.signup(&mut user).await
    }

    /// Performs the signup for the given user.
    #[instrument(skip(self))]
    pub async fn signup(&self, user: &mut User) -> Result<Claims> {
        self.user_repo.create(user).await?;
        // TODO: implement outbox pattern for events publishment
        self.event_srv.emit_user_created(user).await?;

        self.token_srv
            .issue(TokenKind::Session, &user.id.to_string())
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        cache::Cache,
        token::{
            domain::{Claims, Payload, Token, TokenKind},
            service::test::TokenServiceMock,
        },
        user::{
            application::test::{
                new_user_application, EventServiceMock, MailServiceMock, UserRepositoryMock,
            },
            domain::{Credentials, Email, Password, PasswordHash, Preferences, Salt, User},
            error::Error,
        },
    };
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn verify_credentials_when_user_already_exists() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|_: &UserRepositoryMock, email: &Email| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: 999,
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

        let result = user_app.verify_credentials(email, password).await;
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

        let result = user_app.verify_credentials(email, password).await;
        assert!(
            matches!(result, Err(Error::Debug)),
            "got result = {:?}, want error = {:?}",
            result,
            Error::Debug
        )
    }

    #[tokio::test]
    async fn verify_credentials_must_not_fail() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|_: &UserRepositoryMock, _: &Email| Err(Error::NotFound));

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|_: &TokenServiceMock, kind: TokenKind, sub: &str| {
            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut mail_srv = MailServiceMock::default();
        mail_srv.send_credentials_verification_email_fn =
            Some(|_: &MailServiceMock, email: &Email, token: &Token| {
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

        let result = user_app.verify_credentials(email, password).await;
        assert!(matches!(result, Ok(_)), "{:?}", result,)
    }

    #[tokio::test]
    async fn signup_with_token_must_not_fail() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|_: &UserRepositoryMock, user: &mut User| {
            assert_eq!(
                user.credentials.email.as_ref(),
                "username@server.domain",
                "unexpected email"
            );

            user.id = 999;
            Ok(())
        });

        let mut event_srv: EventServiceMock = Default::default();
        event_srv.emit_user_created_fn = Some(|_: &EventServiceMock, user: &User| {
            assert_eq!(user.id, 999, "unexpected user id");
            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|_: &TokenServiceMock, kind: TokenKind, sub: &str| {
            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        token_srv.claims_fn = Some(|_: &TokenServiceMock, token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("credentials"),
            })
        });

        token_srv.revoke_fn = Some(|_: &TokenServiceMock, claims: &Claims| {
            assert_eq!(claims.token.as_ref(), "abc.abc.abc", "unexpected token");
            assert_eq!(
                claims.payload().kind(),
                TokenKind::Verification,
                "unexpected token kind"
            );
            assert_eq!(
                claims.payload().subject(),
                "credentials",
                "unexpected token subject"
            );
            Ok(())
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = Credentials {
            email: Email::try_from("username@server.domain").unwrap(),
            password: PasswordHash::with_salt(&password, &salt).unwrap(),
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("credentials", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);
        user_app.event_srv = Arc::new(event_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let token = user_app.signup_with_token(token).await.unwrap();

        assert_eq!(
            token.payload.kind(),
            TokenKind::Session,
            "expected token of the session kind"
        );
        assert_eq!(
            token.payload.subject(),
            "999",
            "expected user id in token subject"
        );
    }

    #[tokio::test]
    async fn signup_with_invalid_token_must_fail() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|_: &TokenServiceMock, kind: TokenKind, sub: &str| {
            Ok(Claims {
                token: "123.123.123".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        token_srv.claims_fn = Some(|_: &TokenServiceMock, token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");
            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("credentials"),
            })
        });

        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = Credentials {
            email: Email::try_from("username@server.domain").unwrap(),
            password: PasswordHash::with_salt(&password, &salt).unwrap(),
        };

        let mut user_app = new_user_application();
        user_app
            .cache
            .save("credentials", credentials, Duration::from_secs(60))
            .await
            .unwrap();

        user_app.hash_length = 32;
        user_app.token_srv = Arc::new(token_srv);

        let token = Token::try_from("abc.abc.abc".to_string()).unwrap();
        let result = user_app.signup_with_token(token).await;
        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }

    #[tokio::test]
    async fn signup_must_not_fail() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.create_fn = Some(|_: &UserRepositoryMock, user: &mut User| {
            user.id = 999;
            Ok(())
        });

        let mut event_srv: EventServiceMock = Default::default();
        event_srv.emit_user_created_fn = Some(|_: &EventServiceMock, _: &User| Ok(()));

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|_: &TokenServiceMock, kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Session, "unexpected token kind");
            assert_eq!(sub, "999", "unexpected token subject");

            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);
        user_app.event_srv = Arc::new(event_srv);

        let email = Email::try_from("username@server.domain").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let salt = Salt::with_length(32).unwrap();
        let credentials = Credentials {
            email,
            password: PasswordHash::with_salt(&password, &salt).unwrap(),
        };

        let mut user = User {
            id: 0,
            credentials,
            preferences: Preferences::default(),
        };

        let claims = user_app.signup(&mut user).await.unwrap();

        assert_eq!(user.id, 999);
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
