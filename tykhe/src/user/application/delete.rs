use super::{MailService, UserApplication, UserRepository};
use crate::cache::Cache;
use crate::macros::on_error;
use crate::multi_factor::domain::Otp;
use crate::multi_factor::service::MultiFactorService;
use crate::secret::service::SecretRepository;
use crate::token::domain::{Token, TokenKind};
use crate::token::service::TokenService;
use crate::user::domain::{Password, UserID};
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
    /// Given a valid session token and credentials, performs the deletion of the corresponding user.
    #[with_token(kind(Session))]
    #[instrument(skip(self, password, otp))]
    pub async fn delete_with_token(
        &self,
        token: Token,
        password: Password,
        otp: Option<Otp>,
    ) -> Result<()> {
        if let Err(error) = self.token_srv.revoke(&claims).await {
            error!(error = error.to_string(), "revoking session token");
        }

        self.delete(user_id, password, otp).await
    }

    /// Given a valid user ID and credentials, performs the deletion of the corresponding user.
    #[instrument(skip(self, password, otp))]
    pub async fn delete(
        &self,
        user_id: UserID,
        password: Password,
        otp: Option<Otp>,
    ) -> Result<()> {
        let user = self.user_repo.find(user_id).await?;

        if !user.password_matches(&password)? {
            return Err(Error::WrongCredentials);
        }

        self.multi_factor_srv.verify(&user, otp.as_ref()).await?;

        if let Err(error) = self.secret_repo.delete_by_owner(&user).await {
            error!(error = error.to_string(), "deleting all user secrets");
        }

        self.user_repo.delete(&user).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        multi_factor::{domain::Otp, service::tests::MultiFactorServiceMock},
        secret::service::tests::SecretRepositoryMock,
        token::{
            domain::{Claims, Payload, Token, TokenKind},
            service::tests::TokenServiceMock,
        },
        user::{
            application::tests::{new_user_application, UserRepositoryMock},
            domain::{Credentials, Password, PasswordHash, Preferences, Salt, User, UserID},
            error::Error,
        },
    };
    use std::{str::FromStr, sync::Arc, time::Duration};

    #[tokio::test]
    async fn delete() {
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

        user_repo.delete_fn = Some(|user: &User| {
            let want_user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
            assert_eq!(user.id, want_user_id, "unexpected user id");
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

        let mut secret_repo = SecretRepositoryMock::default();
        secret_repo.fn_delete_by_owner = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.secret_repo = Arc::new(secret_repo);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        user_app.delete(user_id, password, None).await.unwrap();
    }

    #[tokio::test]
    async fn delete_when_secrets_deletion_fails() {
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

        user_repo.delete_fn = Some(|user: &User| {
            let want_user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
            assert_eq!(user.id, want_user_id, "unexpected user id");
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

        let mut secret_repo = SecretRepositoryMock::default();
        secret_repo.fn_delete_by_owner = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Err(crate::secret::error::Error::Debug)
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.secret_repo = Arc::new(secret_repo);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        user_app.delete(user_id, password, None).await.unwrap();
    }

    #[tokio::test]
    async fn delete_when_invalid_password() {
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

        let mut user_app = new_user_application();
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC1234&".to_string()).unwrap();

        let result = user_app.delete(user_id, password, None).await;
        assert!(
            matches!(result, Err(Error::WrongCredentials)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongCredentials
        );
    }

    #[tokio::test]
    async fn delete_when_multi_factor_fails() {
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
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app
            .delete(
                user_id,
                password,
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
    async fn delete_with_token() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
            })
        });

        token_srv.revoke_fn = Some(|claims: &Claims| {
            assert_eq!(
                claims.payload().subject(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected token subject"
            );

            assert_eq!(
                claims.payload().kind(),
                TokenKind::Session,
                "unexpected token kind"
            );

            Ok(())
        });

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

        user_repo.delete_fn = Some(|user: &User| {
            let want_user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
            assert_eq!(user.id, want_user_id, "unexpected user id");
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

        let mut secret_repo = SecretRepositoryMock::default();
        secret_repo.fn_delete_by_owner = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.secret_repo = Arc::new(secret_repo);
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        user_app
            .delete_with_token(token, password, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_with_token_when_token_revoke_fails() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
            })
        });

        token_srv.revoke_fn = Some(|claims: &Claims| {
            assert_eq!(
                claims.payload().subject(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected token subject"
            );

            assert_eq!(
                claims.payload().kind(),
                TokenKind::Session,
                "unexpected token kind"
            );

            Err(crate::token::error::Error::Debug)
        });

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

        user_repo.delete_fn = Some(|user: &User| {
            let want_user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
            assert_eq!(user.id, want_user_id, "unexpected user id");
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

        let mut secret_repo = SecretRepositoryMock::default();
        secret_repo.fn_delete_by_owner = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.secret_repo = Arc::new(secret_repo);
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        user_app
            .delete_with_token(token, password, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_with_token_when_invalid_token() {
        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Verification, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
            })
        });

        let mut user_app = new_user_application();
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();

        let result = user_app.delete_with_token(token, password, None).await;

        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }
}
