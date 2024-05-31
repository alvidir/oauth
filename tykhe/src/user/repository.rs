use super::domain::{
    Credentials, Email, EventKind, PasswordHash, Preferences, UserEventPayload, UserID,
};
use super::error::{Error, Result};
use super::{application::UserRepository, domain::User};
use crate::base64;
use crate::event::repository::PostgresEventRepository;
use crate::macros::on_error;
use crate::multi_factor::domain::MultiFactorMethod;
use crate::postgres::on_query_error;
use crate::secret::domain::SecretKind;
use crate::secret::{domain::Secret, repository::PostgresSecretRepository};
use async_trait::async_trait;
use futures::join;
use sqlx::error::Error as SqlError;
use sqlx::postgres::PgPool;
use std::str::FromStr;

const QUERY_INSERT_USER: &str =
    "INSERT INTO users (uuid, name, email, actual_email, password, multi_factor_method) VALUES ($1, $2, $3, $4, $5, $6)";
const QUERY_FIND_USER: &str =
    "SELECT uuid, email, password, multi_factor_method FROM users WHERE uuid = $1";
const QUERY_FIND_USER_BY_EMAIL: &str =
    "SELECT uuid, email, password, multi_factor_method FROM users WHERE email = $1 OR actual_email = $1";
const QUERY_FIND_USER_BY_NAME: &str =
    "SELECT uuid, email, password, multi_factor_method FROM users WHERE name = $1";
const QUERY_UPDATE_USER: &str =
    "UPDATE users SET name = $1, email = $2, actual_email = $3, password = $4, multi_factor_method = $5 WHERE uuid = $6";
const QUERY_DELETE_USER: &str = "DELETE FROM users WHERE uuid = $1";

// uuid, email, password, multi_factor_method
type PostgresUserRow = (String, String, String, Option<String>);

pub struct PostgresUserRepository<'a> {
    pub pool: &'a PgPool,
}

impl<'a> PostgresUserRepository<'a> {
    fn construct(row: PostgresUserRow, salt: Secret) -> Result<User> {
        Ok(User {
            id: UserID::from_str(&row.0)?,
            credentials: Credentials {
                email: row.1.try_into()?,
                password: PasswordHash {
                    hash: row.2,
                    salt: base64::encode(salt.data()).try_into()?,
                },
            },
            preferences: Preferences {
                multi_factor: row
                    .3
                    .as_deref()
                    .map(MultiFactorMethod::from_str)
                    .transpose()
                    .map_err(on_error!(
                        Error,
                        "converting string into multi factor method"
                    ))?,
            },
        })
    }
}

#[async_trait]
impl<'a> UserRepository for PostgresUserRepository<'a> {
    async fn find(&self, user_id: UserID) -> Result<User> {
        let select_user = sqlx::query_as(QUERY_FIND_USER)
            .bind(user_id.to_string())
            .fetch_one(self.pool);

        let (secret_result, user_result) = join!(
            PostgresSecretRepository::find_by_owner_and_kind(self.pool, user_id, SecretKind::Salt),
            select_user,
        );

        let salt_secret = secret_result.map_err(Error::from)?;

        let user_row = user_result.map_err(on_query_error!(
            "performing select user by id query on postgres"
        ))?;

        Self::construct(user_row, salt_secret)
    }

    async fn find_by_email(&self, email: &Email) -> Result<User> {
        let user_row: PostgresUserRow = sqlx::query_as(QUERY_FIND_USER_BY_EMAIL)
            .bind(email.as_ref())
            .fetch_one(self.pool)
            .await
            .map_err(on_query_error!(
                "performing select user by email query on postgres"
            ))?;

        let salt_secret = PostgresSecretRepository::find_by_owner_and_kind(
            self.pool,
            UserID::from_str(&user_row.0)?,
            SecretKind::Salt,
        )
        .await?;

        Self::construct(user_row, salt_secret)
    }

    async fn find_by_name(&self, target: &str) -> Result<User> {
        let user_row: PostgresUserRow = sqlx::query_as(QUERY_FIND_USER_BY_NAME)
            .bind(target)
            .fetch_one(self.pool)
            .await
            .map_err(on_query_error!(
                "performing select user by name query on postgres"
            ))?;

        let salt_secret = PostgresSecretRepository::find_by_owner_and_kind(
            self.pool,
            UserID::from_str(&user_row.0)?,
            SecretKind::Salt,
        )
        .await?;

        Self::construct(user_row, salt_secret)
    }

    async fn create(&self, user: &User) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(on_error!(Error, "starting postgres transaction"))?;

        sqlx::query(QUERY_INSERT_USER)
            .bind(user.id.to_string())
            .bind(user.credentials.email.username())
            .bind(user.credentials.email.as_ref())
            .bind(user.credentials.email.actual_email().as_ref())
            .bind(user.credentials.password.as_ref())
            .bind(
                user.preferences
                    .multi_factor
                    .as_ref()
                    .map(ToString::to_string),
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(on_error!(Error, "performing insert user query on postgres"))?;

        let salt = Secret::new_salt(user);
        PostgresSecretRepository::create(&mut *tx, &salt).await?;
        PostgresEventRepository::create(&mut *tx, UserEventPayload::new(EventKind::Created, user))
            .await?;

        tx.commit()
            .await
            .map_err(on_error!(Error, "commiting postgres transaction"))?;

        Ok(())
    }

    async fn save(&self, user: &User) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(on_error!(Error, "starting postgres transaction"))?;

        sqlx::query(QUERY_UPDATE_USER)
            .bind(user.credentials.email.username())
            .bind(user.credentials.email.as_ref())
            .bind(user.credentials.email.actual_email().as_ref())
            .bind(user.credentials.password.as_ref())
            .bind(
                user.preferences
                    .multi_factor
                    .as_ref()
                    .map(ToString::to_string),
            )
            .bind(user.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(on_error!(Error, "performing update user query on postgres"))?;

        PostgresSecretRepository::delete_by_owner_and_kind(&mut *tx, user.id, SecretKind::Salt)
            .await?;

        let salt = Secret::new_salt(user);
        PostgresSecretRepository::create(&mut *tx, &salt).await?;

        tx.commit()
            .await
            .map_err(on_error!(Error, "commiting postgres transaction"))?;

        Ok(())
    }

    async fn delete(&self, user: &User) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(on_error!(Error, "starting postgres transaction"))?;

        sqlx::query(QUERY_DELETE_USER)
            .bind(user.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(on_error!(Error, "performing delete query on postgres"))?;

        PostgresEventRepository::create(&mut *tx, UserEventPayload::new(EventKind::Deleted, user))
            .await?;

        tx.commit()
            .await
            .map_err(on_error!(Error, "commiting postgres transaction"))?;

        Ok(())
    }
}
