pub mod delete;
pub mod multi_factor;
pub mod reset;
pub mod signup;

use super::domain::{Email, User, UserID};
use super::error::Result;
use crate::token::domain::Token;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait UserRepository {
    async fn find(&self, id: UserID) -> Result<User>;
    async fn find_by_email(&self, email: &Email) -> Result<User>;
    async fn find_by_name(&self, name: &str) -> Result<User>;
    async fn create(&self, user: &User) -> Result<()>;
    async fn save(&self, user: &User) -> Result<()>;
    async fn delete(&self, user: &User) -> Result<()>;
}

pub trait MailService {
    fn send_credentials_verification_email(&self, to: &Email, token: &Token) -> Result<()>;
    fn send_credentials_reset_email(&self, to: &Email, token: &Token) -> Result<()>;
}

pub struct UserApplication<U, S, T, F, M, C> {
    pub hash_length: usize,
    pub user_repo: Arc<U>,
    pub secret_repo: Arc<S>,
    pub token_srv: Arc<T>,
    pub multi_factor_srv: Arc<F>,
    pub mail_srv: Arc<M>,
    pub cache: Arc<C>,
}

#[cfg(test)]
mod tests {
    use super::{MailService, UserApplication, UserRepository};
    use crate::{
        cache::tests::InMemoryCache,
        multi_factor::service::tests::MultiFactorServiceMock,
        secret::service::tests::SecretRepositoryMock,
        token::{domain::Token, service::tests::TokenServiceMock},
        user::{
            domain::{Email, User, UserID},
            error::{Error, Result},
        },
    };
    use async_trait::async_trait;

    type FindFn = fn(id: UserID) -> Result<User>;
    type FindByEmailFn = fn(email: &Email) -> Result<User>;
    type FindByNameFn = fn(name: &str) -> Result<User>;
    type CreateFn = fn(user: &User) -> Result<()>;
    type SaveFn = fn(user: &User) -> Result<()>;
    type DeleteFn = fn(user: &User) -> Result<()>;

    pub fn new_user_application() -> UserApplication<
        UserRepositoryMock,
        SecretRepositoryMock,
        TokenServiceMock,
        MultiFactorServiceMock,
        MailServiceMock,
        InMemoryCache,
    > {
        UserApplication {
            hash_length: Default::default(),
            user_repo: Default::default(),
            secret_repo: Default::default(),
            token_srv: Default::default(),
            multi_factor_srv: Default::default(),
            mail_srv: Default::default(),
            cache: Default::default(),
        }
    }

    #[derive(Debug, Default)]
    pub struct UserRepositoryMock {
        pub find_fn: Option<FindFn>,
        pub find_by_email_fn: Option<FindByEmailFn>,
        pub find_by_name_fn: Option<FindByNameFn>,
        pub create_fn: Option<CreateFn>,
        pub save_fn: Option<SaveFn>,
        pub delete_fn: Option<DeleteFn>,
    }

    #[async_trait]
    impl UserRepository for UserRepositoryMock {
        async fn find(&self, id: UserID) -> Result<User> {
            if let Some(find_fn) = self.find_fn {
                return find_fn(id);
            }

            Err(Error::Debug)
        }

        async fn find_by_email(&self, email: &Email) -> Result<User> {
            if let Some(find_by_email_fn) = self.find_by_email_fn {
                return find_by_email_fn(email);
            }

            Err(Error::Debug)
        }

        async fn find_by_name(&self, name: &str) -> Result<User> {
            if let Some(find_by_name_fn) = self.find_by_name_fn {
                return find_by_name_fn(name);
            }

            Err(Error::Debug)
        }

        async fn create(&self, user: &User) -> Result<()> {
            if let Some(create_fn) = self.create_fn {
                return create_fn(user);
            }

            Err(Error::Debug)
        }

        async fn save(&self, user: &User) -> Result<()> {
            if let Some(save_fn) = self.save_fn {
                return save_fn(user);
            }

            Err(Error::Debug)
        }

        async fn delete(&self, user: &User) -> Result<()> {
            if let Some(delete_fn) = self.delete_fn {
                return delete_fn(user);
            }

            Err(Error::Debug)
        }
    }

    pub type SendCredentialsVerificationEmailFn = fn(to: &Email, token: &Token) -> Result<()>;
    pub type SendCredentialsResetEmailFn = fn(to: &Email, token: &Token) -> Result<()>;

    #[derive(Debug, Default)]
    pub struct MailServiceMock {
        pub send_credentials_verification_email_fn: Option<SendCredentialsVerificationEmailFn>,
        pub send_credentials_reset_email_fn: Option<SendCredentialsResetEmailFn>,
    }

    impl MailService for MailServiceMock {
        fn send_credentials_verification_email(&self, to: &Email, token: &Token) -> Result<()> {
            if let Some(send_credentials_verification_email_fn) =
                self.send_credentials_verification_email_fn
            {
                return send_credentials_verification_email_fn(to, token);
            }

            Err(Error::Debug)
        }

        fn send_credentials_reset_email(&self, to: &Email, token: &Token) -> Result<()> {
            if let Some(send_credentials_reset_email_fn) = self.send_credentials_reset_email_fn {
                return send_credentials_reset_email_fn(to, token);
            }

            Err(Error::Debug)
        }
    }
}
