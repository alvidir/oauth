use super::{MailService, UserApplication, UserRepository};
use crate::cache::Cache;
use crate::macros::on_error;
use crate::multi_factor::domain::Otp;
use crate::multi_factor::service::MultiFactorService;
use crate::secret::service::SecretRepository;
use crate::token::domain::{Token, TokenKind};
use crate::token::service::TokenService;
use crate::user::domain::{Email, Password, PasswordHash, Salt, UserID};
use crate::user::error::{Error, Result};
use std::str::FromStr;

impl<U, S, T, F, M, C> UserApplication<U, S, T, F, M, C>
where
    U: UserRepository,
    S: SecretRepository,
    T: TokenService,
    F: MultiFactorService,
    M: MailService,
    C: Cache,
{
    /// Sends an email with the reset token to be passed as parameter to the reset_with_token method.
    #[instrument(skip(self))]
    pub async fn confirm_password_reset(&self, email: Email) -> Result<()> {
        let user = self.user_repo.find_by_email(&email).await?;

        let claims = self
            .token_srv
            .issue(TokenKind::Reset, &user.id.to_string())
            .await?;

        self.mail_srv
            .send_credentials_reset_email(&email, claims.token())?;

        Ok(())
    }

    /// Given a valid user ID and one-time password, if needed, resets the password of the corresponding user by the given new_password.
    #[derive_with_token_fn(kind(Reset), skip(user_id))]
    #[instrument(skip(self, new_password, otp))]
    pub async fn reset_password(
        &self,
        user_id: UserID,
        new_password: Password,
        otp: Option<Otp>,
    ) -> Result<()> {
        let mut user = self.user_repo.find(user_id).await?;
        self.multi_factor_srv.verify(&user, otp.as_ref()).await?;

        if user.password_matches(&new_password)? {
            // is the same password, nothing have to be done.
            return Ok(());
        }

        let salt = Salt::with_length(self.hash_length)?;
        user.credentials.password = PasswordHash::with_salt(&new_password, &salt)?;
        self.user_repo.save(&user).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        multi_factor::{domain::Otp, service::tests::MultiFactorServiceMock},
        token::{
            domain::{Claims, Payload, Token, TokenKind},
            service::tests::TokenServiceMock,
        },
        user::{
            application::tests::{new_user_application, MailServiceMock, UserRepositoryMock},
            domain::{Credentials, Email, Password, PasswordHash, Preferences, Salt, User, UserID},
            error::Error,
        },
    };
    use std::{str::FromStr, sync::Arc, time::Duration};

    #[tokio::test]
    async fn confirm_password_reset() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|email: &Email| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                credentials: Credentials {
                    email: email.clone(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
                preferences: Preferences::default(),
            })
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.issue_fn = Some(|kind: TokenKind, sub: &str| {
            assert_eq!(kind, TokenKind::Reset, "unexpected token kind");
            assert_eq!(
                sub, "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected token subject"
            );

            Ok(Claims {
                token: "abc.abc.abc".to_string().try_into().unwrap(),
                payload: Payload::new(kind, Duration::from_secs(60)).with_subject(sub),
            })
        });

        let mut mail_srv = MailServiceMock::default();
        mail_srv.send_credentials_reset_email_fn = Some(|email: &Email, token: &Token| {
            assert_eq!(email.as_ref(), "username@server.domain", "unexpected email");
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);
        user_app.mail_srv = Arc::new(mail_srv);

        let email = Email::try_from("username@server.domain").unwrap();
        user_app.confirm_password_reset(email).await.unwrap();
    }

    #[tokio::test]
    async fn confirm_password_reset_when_user_does_not_exists() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_by_email_fn = Some(|_: &Email| Err(Error::NotFound));

        let mut mail_srv = MailServiceMock::default();
        mail_srv.send_credentials_reset_email_fn = Some(|_: &Email, _: &Token| {
            assert!(false, "unexpected execution");
            Err(Error::Debug)
        });

        let mut user_app = new_user_application();
        user_app.user_repo = Arc::new(user_repo);
        user_app.mail_srv = Arc::new(mail_srv);

        let email = Email::try_from("username@server.domain").unwrap();
        let result = user_app.confirm_password_reset(email).await;

        assert!(
            matches!(result, Err(Error::NotFound)),
            "got result = {:?}, want error = {}",
            result,
            Error::NotFound
        )
    }

    #[tokio::test]
    async fn reset_password() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_fn = Some(|user_id: UserID| {
            assert_eq!(
                &user_id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                credentials: Credentials {
                    email: "username@server.domain".try_into().unwrap(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
                preferences: Preferences::default(),
            })
        });

        user_repo.save_fn = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Ok(())
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.verify_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            assert_eq!(otp, None, "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let new_password = Password::try_from("abcABC1234&".to_string()).unwrap();

        user_app
            .reset_password(
                UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                new_password,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reset_password_when_new_is_same_as_before() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_fn = Some(|user_id: UserID| {
            assert_eq!(
                &user_id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                credentials: Credentials {
                    email: "username@server.domain".try_into().unwrap(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
                preferences: Preferences::default(),
            })
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.verify_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            assert_eq!(otp, None, "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let new_password = Password::try_from("abcABC123&".to_string()).unwrap();

        user_app
            .reset_password(
                UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                new_password,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reset_password_when_multi_factor_fails() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_fn = Some(|user_id: UserID| {
            assert_eq!(
                &user_id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                credentials: Credentials {
                    email: "username@server.domain".try_into().unwrap(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
                preferences: Preferences::default(),
            })
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.verify_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            assert_eq!(
                otp,
                Some(&"123456".to_string().try_into().unwrap()),
                "unexpected otp"
            );
            Err(crate::multi_factor::error::Error::Invalid)
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let new_password = Password::try_from("abcABC1234&".to_string()).unwrap();

        let result = user_app
            .reset_password(
                UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                new_password,
                Some("123456".to_string().try_into().unwrap()),
            )
            .await;

        assert!(
            matches!(
                result,
                Err(Error::MultiFactor(
                    crate::multi_factor::error::Error::Invalid
                ))
            ),
            "got result = {:?}, want error = {}",
            result,
            Error::MultiFactor(crate::multi_factor::error::Error::Invalid)
        );
    }

    #[tokio::test]
    async fn reset_password_with_token() {
        let mut user_repo = UserRepositoryMock::default();
        user_repo.find_fn = Some(|user_id: UserID| {
            assert_eq!(
                &user_id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            let password = Password::try_from("abcABC123&".to_string()).unwrap();
            let salt = Salt::with_length(32).unwrap();

            Ok(User {
                id: UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap(),
                credentials: Credentials {
                    email: "username@server.domain".try_into().unwrap(),
                    password: PasswordHash::with_salt(&password, &salt).unwrap(),
                },
                preferences: Preferences::default(),
            })
        });

        user_repo.save_fn = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Ok(())
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.verify_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            assert_eq!(otp, None, "unexpected otp");
            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Reset, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
            })
        });

        let mut user_app = new_user_application();
        user_app.hash_length = 32;
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC1234&".to_string()).unwrap();

        user_app
            .reset_password_with_token(token, password, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reset_password_with_token_when_invalid_token() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("reset"),
            })
        });

        let mut user_app = new_user_application();
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app
            .reset_password_with_token(token, password, None)
            .await;

        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }
}
