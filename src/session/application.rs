use crate::cache::Cache;
use crate::crypto;
use crate::result::{Error, Result};
use crate::secret::application::SecretRepository;
use crate::secret::domain::SecretKind;
use crate::token::application::TokenApplication;
use crate::token::domain::TokenKind;
use crate::user::application::UserRepository;
use crate::user::domain::{Email, Password};
use std::sync::Arc;

pub struct SessionApplication<'a, U: UserRepository, S: SecretRepository, C: Cache> {
    pub user_repo: Arc<U>,
    pub secret_repo: Arc<S>,
    pub token_app: Arc<TokenApplication<'a, C>>,
    pub pwd_sufix: &'a str,
}

impl<'a, U: UserRepository, S: SecretRepository, C: Cache> SessionApplication<'a, U, S, C> {
    /// TODO: create entity Identity and use Credentials here + Totp
    #[instrument(skip(self))]
    pub async fn login(&self, ident: &str, pwd: &str, totp: &str) -> Result<String> {
        let user = {
            if Email::REGEX.is_match(ident) {
                self.user_repo.find_by_email(&ident.try_into()?).await
            } else {
                self.user_repo.find_by_name(ident).await
            }
        }
        .map_err(|_| Error::WrongCredentials)?;

        if Password::try_from(pwd)
            .map(|pwd| pwd.digest(self.pwd_sufix))
            .is_ok_and(|pwd| {
                user.credentials
                    .password
                    .map(|user_pwd| user_pwd == pwd)
                    .unwrap_or_default()
            })
        {
            return Err(Error::WrongCredentials);
        }

        self.secret_repo
            .find_by_owner_and_kind(user.id, SecretKind::Totp)
            .await
            .and_then(|secret| crypto::verify_totp(secret.data(), totp))
            .map_err(|_| Error::Unauthorized)?;

        let token = self
            .token_app
            .generate(TokenKind::Session, &user.id.to_string())?;

        self.token_app.store(&token).await?;
        self.token_app.sign(&token)
    }

    #[instrument(skip(self))]
    pub async fn logout(&self, token: &str) -> Result<()> {
        logout_strategy::<C>(&self.token_app, token).await
    }
}

pub(super) async fn logout_strategy<'b, C: Cache>(
    token_app: &TokenApplication<'b, C>,
    token: &str,
) -> Result<()> {
    let token = token_app.decode(token)?;
    if !token.knd.is_session() {
        return Err(Error::InvalidToken);
    }

    token_app.revoke(&token.jti).await
}

#[cfg(test)]
pub mod tests {
    use super::SessionApplication;
    use crate::cache::tests::InMemoryCache;
    use crate::secret::application::tests::SecretRepositoryMock;
    use crate::secret::domain::{Secret, SecretKind};
    use crate::token::application::tests::{
        new_token, new_token_application, PRIVATE_KEY, PUBLIC_KEY,
    };
    use crate::token::domain::{Token, TokenKind};
    use crate::user::{application::tests::UserRepositoryMock, domain::User};
    use crate::{
        crypto,
        result::{Error, Result},
    };
    use std::sync::Arc;

    pub fn new_session_application<'a>(
    ) -> SessionApplication<'a, UserRepositoryMock, SecretRepositoryMock, InMemoryCache> {
        let user_repo = UserRepositoryMock::default();
        let secret_repo = SecretRepositoryMock::default();
        let token_app = new_token_application();

        SessionApplication {
            user_repo: Arc::new(user_repo),
            secret_repo: Arc::new(secret_repo),
            token_app: Arc::new(token_app),
            pwd_sufix: "::test",
        }
    }

    #[tokio::test]
    async fn login_by_email_should_not_fail() {
        let secret_repo = SecretRepositoryMock {
            fn_find_by_owner_and_kind: Some(
                |_: &SecretRepositoryMock, _: i32, _: SecretKind| -> Result<Secret> {
                    Err(Error::NotFound)
                },
            ),
            ..Default::default()
        };

        let mut app = new_session_application();
        app.secret_repo = Arc::new(secret_repo);

        let token = app
            .login("username@server.domain", "abcABC123&", "")
            .await
            .map_err(|err| {
                println!(
                    "-\tlogin_by_email_should_not_fail has failed with error {}",
                    err
                )
            })
            .unwrap();
        let session: Token = crypto::decode_jwt(&PUBLIC_KEY, &token).unwrap();

        assert_eq!(session.sub, "123".to_string());
    }

    #[tokio::test]
    async fn login_by_username_should_not_fail() {
        let secret_repo = SecretRepositoryMock {
            fn_find_by_owner_and_kind: Some(
                |_: &SecretRepositoryMock, _: i32, _: SecretKind| -> Result<Secret> {
                    Err(Error::NotFound)
                },
            ),
            ..Default::default()
        };

        let mut app = new_session_application();
        app.secret_repo = Arc::new(secret_repo);
        let token = app
            .login("username", "abcABC123&", "")
            .await
            .map_err(|err| {
                println!(
                    "-\tlogin_by_username_should_not_fail has failed with error {}",
                    err
                )
            })
            .unwrap();
        let session: Token = crypto::decode_jwt(&PUBLIC_KEY, &token).unwrap();
        assert_eq!(session.sub, "123".to_string());
    }

    #[tokio::test]
    async fn login_with_totp_should_not_fail() {
        let app = new_session_application();
        let code = crypto::generate_totp(b"secret_data").unwrap().generate();
        let token = app
            .login("username", "abcABC123&", &code)
            .await
            .map_err(|err| {
                println!(
                    "-\tlogin_with_totp_should_not_fail has failed with error {}",
                    err
                )
            })
            .unwrap();
        let session: Token = crypto::decode_jwt(&PUBLIC_KEY, &token).unwrap();
        assert_eq!(session.sub, "123".to_string());
    }

    #[tokio::test]
    async fn login_user_not_found_should_fail() {
        let user_repo = UserRepositoryMock {
            fn_find_by_email: Some(|_: &UserRepositoryMock, _: &str| -> Result<User> {
                Err(Error::WrongCredentials)
            }),
            ..Default::default()
        };

        let mut app = new_session_application();
        app.user_repo = Arc::new(user_repo);

        let code = crypto::generate_totp(b"secret_data").unwrap().generate();

        app.login("username@server.domain", "abcABC123&", &code)
            .await
            .map_err(|err| assert_eq!(err.to_string(), Error::WrongCredentials.to_string()))
            .unwrap_err();
    }

    #[tokio::test]
    async fn login_wrong_password_should_fail() {
        let app = new_session_application();
        let code = crypto::generate_totp(b"secret_data").unwrap().generate();
        app.login("username", "fake_password", &code)
            .await
            .map_err(|err| assert_eq!(err.to_string(), Error::WrongCredentials.to_string()))
            .unwrap_err();
    }

    #[tokio::test]
    async fn login_wrong_totp_should_fail() {
        let app = new_session_application();

        app.login("username", "abcABC123&", "fake_totp")
            .await
            .map_err(|err| assert_eq!(err.to_string(), Error::Unauthorized.to_string()))
            .unwrap_err();
    }

    #[tokio::test]
    async fn logout_should_not_fail() {
        let token = crypto::sign_jwt(&PRIVATE_KEY, new_token(TokenKind::Session)).unwrap();
        let app = new_session_application();

        app.logout(&token)
            .await
            .map_err(|err| println!("-\tlogout_should_not_fail has failed with error {}", err))
            .unwrap();
    }

    #[tokio::test]
    async fn logout_verification_token_kind_should_fail() {
        let token = new_token(TokenKind::Verification);
        let token = crypto::sign_jwt(&PRIVATE_KEY, token).unwrap();
        let app = new_session_application();

        app.logout(&token)
            .await
            .map_err(|err| assert_eq!(err.to_string(), Error::InvalidToken.to_string()))
            .unwrap_err();
    }

    #[tokio::test]
    async fn logout_reset_token_kind_should_fail() {
        let token = new_token(TokenKind::Reset);
        let token = crypto::sign_jwt(&PRIVATE_KEY, token).unwrap();
        let app = new_session_application();

        app.logout(&token)
            .await
            .map_err(|err| assert_eq!(err.to_string(), Error::InvalidToken.to_string()))
            .unwrap_err();
    }
}
