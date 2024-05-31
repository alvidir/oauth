use super::{
    error::{Error, Result},
    service::EventRepository,
};
use crate::macros::on_error;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{PgExecutor, PgPool};
use std::{
    collections::hash_map::DefaultHasher,
    fmt::Debug,
    hash::{Hash, Hasher},
};

const QUERY_INSERT_EVENT: &str = "INSERT INTO events (checksum, payload) VALUES ($1, $2)";
const QUERY_SELECT_EVENTS: &str = "SELECT payload FROM events ORDER BY created_at ASC LIMIT $1";
const QUERY_DELETE_EVENT: &str = "DELETE FROM events WHERE id = $1";

// payload
type PostgresEventRow = (String,);

pub struct PostgresEventRepository<'a> {
    pub pool: &'a PgPool,
}

impl<'a> PostgresEventRepository<'a> {
    #[instrument]
    fn checksum<E>(event: &E) -> String
    where
        E: Debug + Hash,
    {
        let mut hasher = DefaultHasher::new();
        event.hash(&mut hasher);

        hasher.finish().to_string()
    }

    #[instrument(skip(executor))]
    pub async fn create<'b, X, E>(executor: X, event: E) -> Result<()>
    where
        X: PgExecutor<'b>,
        E: Debug + Hash + Serialize,
    {
        let checksum = PostgresEventRepository::checksum(&event);
        let payload = serde_json::to_string(&event)
            .map_err(on_error!(Error, "serializing event payload into json"))?;

        sqlx::query(QUERY_INSERT_EVENT)
            .bind(checksum.as_str())
            .bind(payload.as_str())
            .fetch_one(executor)
            .await
            .map_err(on_error!(Error, "performing insert query on postgres"))?;

        Ok(())
    }

    #[instrument(skip(executor))]
    async fn delete<'b, X, E>(executor: X, event: E) -> Result<()>
    where
        X: PgExecutor<'b>,
        E: Debug + Hash,
    {
        let checksum = PostgresEventRepository::checksum(&event);
        sqlx::query(QUERY_DELETE_EVENT)
            .bind(checksum.as_str())
            .fetch_one(executor)
            .await
            .map_err(on_error!(Error, "performing delete query on postgres"))?;

        Ok(())
    }
}

#[async_trait]
impl<'a> EventRepository for PostgresEventRepository<'a> {
    #[instrument(skip(self))]
    async fn list<E>(&self, limit: usize) -> Result<Vec<E>>
    where
        E: Debug + DeserializeOwned + Send,
    {
        let result: Vec<PostgresEventRow> = sqlx::query_as(QUERY_SELECT_EVENTS)
            .bind(limit as i32)
            .fetch_all(self.pool)
            .await
            .map_err(on_error!(Error, "performing select query on postgres"))?;

        result
            .into_iter()
            .map(|row| row.0)
            .map(|payload| serde_json::from_str(&payload))
            .map(|de| de.map_err(Error::from))
            .collect()
    }

    #[instrument(skip(self))]
    async fn create<E>(&self, event: E) -> Result<()>
    where
        E: Debug + Hash + Serialize + Send,
    {
        Self::create(self.pool, event).await
    }

    #[instrument(skip(self))]
    async fn delete<E>(&self, event: E) -> Result<()>
    where
        E: Debug + Hash + Send,
    {
        Self::delete(self.pool, event).await
    }
}
