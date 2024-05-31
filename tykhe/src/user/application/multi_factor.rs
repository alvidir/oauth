use super::{MailService, UserApplication, UserRepository};
use crate::cache::Cache;
use crate::macros::on_error;
use crate::multi_factor::domain::{MultiFactorMethod, Otp};
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
    #[derive_with_token_fn(kind(Session), skip(user_id))]
    #[instrument(skip(self, password, otp))]
    pub async fn enable_multi_factor(
        &self,
        user_id: UserID,
        method: MultiFactorMethod,
        password: Password,
        otp: Option<Otp>,
    ) -> Result<()> {
        let mut user = self.user_repo.find(user_id).await?;

        if !user.password_matches(&password)? {
            return Err(Error::WrongCredentials);
        }

        user.preferences.multi_factor = Some(method);

        self.multi_factor_srv
            .enable(&user, otp.as_ref())
            .await
            .map_err(Error::from)?;

        self.user_repo.save(&user).await.map_err(Into::into)
    }

    #[derive_with_token_fn(kind(Session), skip(user_id))]
    #[instrument(skip(self, password, otp))]
    pub async fn disable_multi_factor(
        &self,
        user_id: UserID,
        method: MultiFactorMethod,
        password: Password,
        otp: Option<Otp>,
    ) -> Result<()> {
        let mut user = self.user_repo.find(user_id).await?;

        if !user.password_matches(&password)? {
            return Err(Error::WrongCredentials);
        }

        self.multi_factor_srv.verify(&user, otp.as_ref()).await?;

        self.multi_factor_srv
            .disable(&user, otp.as_ref())
            .await
            .map_err(Error::from)?;

        user.preferences.multi_factor = None;
        self.user_repo.save(&user).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        multi_factor::{
            domain::{MultiFactorMethod, Otp},
            service::tests::MultiFactorServiceMock,
        },
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
    async fn enable_multi_factor() {
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

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected multi factor method in preferences"
            );

            Ok(())
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.enable_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        user_app
            .enable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enable_multi_factor_when_invalid_password() {
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
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .enable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(result, Err(Error::WrongCredentials)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongCredentials
        );
    }

    #[tokio::test]
    async fn enable_multi_factor_when_enable_fails() {
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
        multi_factor_srv.enable_fn = Some(|_: &User, _: Option<&Otp>| {
            Err(crate::multi_factor::error::Error::Ack("secret".to_string()))
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .enable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(
                result,
                Err(Error::MultiFactor(crate::multi_factor::error::Error::Ack(
                    _
                )))
            ),
            "got result = {:?}, want error = {}",
            result,
            Error::MultiFactor(crate::multi_factor::error::Error::Ack("secret".to_string()))
        );
    }

    #[tokio::test]
    async fn enable_multi_factor_with_token() {
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

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
            })
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.enable_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        user_app
            .enable_multi_factor_with_token(token, MultiFactorMethod::Email, password, Some(otp))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enable_multi_factor_with_token_when_invalid_token() {
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
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .enable_multi_factor_with_token(token, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }

    #[tokio::test]
    async fn disable_multi_factor() {
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
                preferences: Preferences {
                    multi_factor: Some(MultiFactorMethod::Email),
                },
            })
        });

        user_repo.save_fn = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor, None,
                "unexpected multi factor method in preferences"
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

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        multi_factor_srv.disable_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        user_app
            .disable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn disable_multi_factor_with_invalid_password() {
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
                preferences: Preferences {
                    multi_factor: Some(MultiFactorMethod::Email),
                },
            })
        });

        let mut user_app = new_user_application();
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC1234&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .disable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(result, Err(Error::WrongCredentials)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongCredentials
        );
    }

    #[tokio::test]
    async fn disable_multi_factor_when_verification_fails() {
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
                preferences: Preferences {
                    multi_factor: Some(MultiFactorMethod::Email),
                },
            })
        });

        let mut multi_factor_srv = MultiFactorServiceMock::default();
        multi_factor_srv.verify_fn =
            Some(|_: &User, _: Option<&Otp>| Err(crate::multi_factor::error::Error::Invalid));

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .disable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
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
    async fn disable_multi_factor_when_disable_fails() {
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
                preferences: Preferences {
                    multi_factor: Some(MultiFactorMethod::Email),
                },
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
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);

        let user_id = UserID::from_str("bca4ec1c-da63-4d73-bad5-a82fc9853828").unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .disable_multi_factor(user_id, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(
                result,
                Err(Error::MultiFactor(crate::multi_factor::error::Error::Debug))
            ),
            "got result = {:?}, want error = {}",
            result,
            Error::MultiFactor(crate::multi_factor::error::Error::Debug)
        );
    }

    #[tokio::test]
    async fn disable_multi_factor_with_token() {
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
                preferences: Preferences {
                    multi_factor: Some(MultiFactorMethod::Email),
                },
            })
        });

        user_repo.save_fn = Some(|user: &User| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor, None,
                "unexpected multi factor method in preferences"
            );

            Ok(())
        });

        let mut token_srv = TokenServiceMock::default();
        token_srv.claims_fn = Some(|token: Token| {
            assert_eq!(token.as_ref(), "abc.abc.abc", "unexpected token");

            Ok(Claims {
                token,
                payload: Payload::new(TokenKind::Session, Duration::from_secs(60))
                    .with_subject("bca4ec1c-da63-4d73-bad5-a82fc9853828"),
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
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        multi_factor_srv.disable_fn = Some(|user: &User, otp: Option<&Otp>| {
            assert_eq!(
                &user.id.to_string(),
                "bca4ec1c-da63-4d73-bad5-a82fc9853828",
                "unexpected user id"
            );

            assert_eq!(
                user.preferences.multi_factor,
                Some(MultiFactorMethod::Email),
                "unexpected mfa method"
            );

            let want_otp: Otp = "123456".to_string().try_into().unwrap();
            assert_eq!(otp, Some(want_otp).as_ref(), "unexpected otp");
            Ok(())
        });

        let mut user_app = new_user_application();
        user_app.multi_factor_srv = Arc::new(multi_factor_srv);
        user_app.user_repo = Arc::new(user_repo);
        user_app.token_srv = Arc::new(token_srv);

        let token: Token = "abc.abc.abc".to_string().try_into().unwrap();
        let password = Password::try_from("abcABC123&".to_string()).unwrap();
        let otp: Otp = "123456".to_string().try_into().unwrap();

        user_app
            .disable_multi_factor_with_token(token, MultiFactorMethod::Email, password, Some(otp))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn disable_multi_factor_with_token_when_invalid_token() {
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
        let otp: Otp = "123456".to_string().try_into().unwrap();

        let result = user_app
            .disable_multi_factor_with_token(token, MultiFactorMethod::Email, password, Some(otp))
            .await;

        assert!(
            matches!(result, Err(Error::WrongToken)),
            "got result = {:?}, want error = {}",
            result,
            Error::WrongToken
        );
    }
}
