use super::error::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, hash::Hash};

#[async_trait]
pub trait EventRepository {
    async fn list<E>(&self, limit: usize) -> Result<Vec<E>>
    where
        E: Debug + DeserializeOwned + Send;

    async fn create<E>(&self, event: E) -> Result<()>
    where
        E: Debug + Hash + Serialize + Send;

    async fn delete<E>(&self, event: E) -> Result<()>
    where
        E: Debug + Hash + Send;
}

#[async_trait]
pub trait EventService {
    async fn emit<E>(&self, event: E) -> Result<()>
    where
        E: Debug + Serialize + Send;
}
