use super::domain::Identity;
use super::error::{Error, Result};
use crate::macros::on_error;
use crate::multi_factor::domain::Otp;
use crate::multi_factor::service::MultiFactorService;
use crate::secret::service::SecretRepository;
use crate::token::domain::{Claims, Token, TokenKind};
use crate::token::service::TokenService;
use crate::user::application::UserRepository;
use crate::user::domain::{Password, UserID};
use std::str::FromStr;
use std::sync::Arc;

pub struct SessionApplication<U, S, T, F> {
    pub user_repo: Arc<U>,
    pub secret_repo: Arc<S>,
    pub token_srv: Arc<T>,
    pub multi_factor_srv: Arc<F>,
}

impl<U, S, T, F> SessionApplication<U, S, T, F>
where
    U: UserRepository,
    S: SecretRepository,
    T: TokenService,
    F: MultiFactorService,
{
    #[instrument(skip(self, password, otp))]
    pub async fn login(
        &self,
        ident: Identity,
        password: Password,
        otp: Option<Otp>,
    ) -> Result<Claims> {
        let user = match ident {
            Identity::Email(email) => self.user_repo.find_by_email(&email).await,
            Identity::Nick(name) => self.user_repo.find_by_name(&name).await,
        }?;

        if !user.password_matches(&password)? {
            return Error::WrongCredentials.into();
        }

        self.multi_factor_srv
            .verify(&user, otp.as_ref())
            .await
            .map_err(Error::from)?;

        self.token_srv
            .issue(TokenKind::Session, &user.id.to_string())
            .await
            .map_err(Into::into)
    }

    #[with_token(kind(Session))]
    #[instrument(skip(self))]
    pub async fn logout(&self, token: Token) -> Result<()> {
        self.token_srv.revoke(&claims).await.map_err(Into::into)
    }
}

// #[cfg(test)]
// pub mod tests {
//     use super::SessionApplication;
//     use crate::cache::tests::InMemoryCache;
//     use crate::secret::application::tests::SecretRepositoryMock;
//     use crate::secret::domain::{Secret, SecretKind};
//     use crate::token::application::tests::{
//         new_token, new_token_srvlication, PRIVATE_KEY, PUBLIC_KEY,
//     };
//     use crate::token::domain::{Payload, TokenKind};
//     use crate::user::domain::Email;
//     use crate::user::{application::tests::UserRepositoryMock, domain::User};
//     use crate::{
//         crypto,
//         result::{Error, Result},
//     };
//     use std::sync::Arc;

//     pub fn new_session_application<'a>(
//     ) -> SessionApplication<'a, UserRepositoryMock, SecretRepositoryMock, InMemoryCache> {
//         let user_repo = UserRepositoryMock::default();
//         let secret_repo = SecretRepositoryMock::default();
//         let token_srv = new_token_srvlication();

//         SessionApplication {
//             user_repo: Arc::new(user_repo),
//             secret_repo: Arc::new(secret_repo),
//             token_srv: Arc::new(token_srv),
//         }
//     }

//     #[tokio::test]
//     async fn login_by_email_should_not_fail() {
//         let secret_repo = SecretRepositoryMock {
//             fn_find_by_owner_and_kind: Some(
//                 |_: &SecretRepositoryMock, _: i32, _: SecretKind| -> Result<Secret> {
//                     Err(Error::NotFound)
//                 },
//             ),
//             ..Default::default()
//         };

//         let mut app = new_session_application();
//         app.secret_repo = Arc::new(secret_repo);

//         let token = app
//             .login("username@server.domain", "abcABC123&", "")
//             .await
//             .map_err(|err| {
//                 println!(
//                     "-\tlogin_by_email_should_not_fail has failed with error {}",
//                     err
//                 )
//             })
//             .unwrap();

//         let session = token.into_payload(&PUBLIC_KEY).unwrap();
//         assert_eq!(session.sub, "123".to_string());
//     }

//     #[tokio::test]
//     async fn login_by_username_should_not_fail() {
//         let secret_repo = SecretRepositoryMock {
//             fn_find_by_owner_and_kind: Some(
//                 |_: &SecretRepositoryMock, _: i32, _: SecretKind| -> Result<Secret> {
//                     Err(Error::NotFound)
//                 },
//             ),
//             ..Default::default()
//         };

//         let mut app = new_session_application();
//         app.secret_repo = Arc::new(secret_repo);
//         let token = app
//             .login("username", "abcABC123&", "")
//             .await
//             .map_err(|err| {
//                 println!(
//                     "-\tlogin_by_username_should_not_fail has failed with error {}",
//                     err
//                 )
//             })
//             .unwrap();

//         let session = token.into_payload(&PUBLIC_KEY).unwrap();
//         assert_eq!(session.sub, "123".to_string());
//     }

//     #[tokio::test]
//     async fn login_with_totp_should_not_fail() {
//         let app = new_session_application();
//         let code = crypto::generate_totp(b"secret_data").unwrap().generate();
//         let token = app
//             .login("username", "abcABC123&", &code)
//             .await
//             .map_err(|err| {
//                 println!(
//                     "-\tlogin_with_totp_should_not_fail has failed with error {}",
//                     err
//                 )
//             })
//             .unwrap();

//         let session = token.into_payload(&PUBLIC_KEY).unwrap();
//         assert_eq!(session.sub, "123".to_string());
//     }

//     #[tokio::test]
//     async fn login_user_not_found_should_fail() {
//         let user_repo = UserRepositoryMock {
//             fn_find_by_email: Some(|_: &UserRepositoryMock, _: &Email| -> Result<User> {
//                 Err(Error::WrongCredentials)
//             }),
//             ..Default::default()
//         };

//         let mut app = new_session_application();
//         app.user_repo = Arc::new(user_repo);

//         let code = crypto::generate_totp(b"secret_data").unwrap().generate();

//         app.login("username@server.domain", "abcABC123&", &code)
//             .await
//             .map_err(|err| assert_eq!(err.to_string(), Error::WrongCredentials.to_string()))
//             .unwrap_err();
//     }

//     #[tokio::test]
//     async fn login_wrong_password_should_fail() {
//         let app = new_session_application();
//         let code = crypto::generate_totp(b"secret_data").unwrap().generate();
//         app.login("username", "fake_password", &code)
//             .await
//             .map_err(|err| assert_eq!(err.to_string(), Error::WrongCredentials.to_string()))
//             .unwrap_err();
//     }

//     #[tokio::test]
//     async fn login_wrong_totp_should_fail() {
//         let app = new_session_application();

//         app.login("username", "abcABC123&", "fake_totp")
//             .await
//             .map_err(|err| assert_eq!(err.to_string(), Error::Unauthorized.to_string()))
//             .unwrap_err();
//     }

//     #[tokio::test]
//     async fn logout_should_not_fail() {
//         let token = crypto::encode_jwt(&PRIVATE_KEY, new_token(TokenKind::Session)).unwrap();
//         let app = new_session_application();

//         app.logout(&token)
//             .await
//             .map_err(|err| println!("-\tlogout_should_not_fail has failed with error {}", err))
//             .unwrap();
//     }

//     #[tokio::test]
//     async fn logout_verification_token_kind_should_fail() {
//         let token = new_token(TokenKind::Verification);
//         let token = crypto::encode_jwt(&PRIVATE_KEY, token).unwrap();
//         let app = new_session_application();

//         app.logout(&token)
//             .await
//             .map_err(|err| assert_eq!(err.to_string(), Error::InvalidToken.to_string()))
//             .unwrap_err();
//     }

//     #[tokio::test]
//     async fn logout_reset_token_kind_should_fail() {
//         let token = new_token(TokenKind::Reset);
//         let token = crypto::encode_jwt(&PRIVATE_KEY, token).unwrap();
//         let app = new_session_application();

//         app.logout(&token)
//             .await
//             .map_err(|err| assert_eq!(err.to_string(), Error::InvalidToken.to_string()))
//             .unwrap_err();
//     }
// }
