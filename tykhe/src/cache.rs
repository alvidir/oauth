//! Defintion and implementations of the [Cache] trait.

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, Error>;

impl<T> From<Error> for Result<T> {
    fn from(error: Error) -> Self {
        Err(error)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("resource not found")]
    NotFound,
    #[error("{0}")]
    Expiration(#[from] std::num::TryFromIntError),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[cfg(feature = "redis-cache")]
    #[error("{0}")]
    Redis(#[from] reool::RedisError),
    #[cfg(feature = "redis-cache")]
    #[error("{0}")]
    Checkout(#[from] reool::CheckoutError),
    #[cfg(test)]
    #[error("unexpected error")]
    Debug,
}

impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }
}

/// Represents a general purpose cache.
#[async_trait]
pub trait Cache {
    async fn find<T>(&self, key: &str) -> Result<T>
    where
        T: DeserializeOwned;
    async fn save<T>(&self, key: &str, value: T, expire: Duration) -> Result<()>
    where
        T: Serialize + Send + Sync + Debug;
    async fn delete(&self, key: &str) -> Result<()>;
}

#[cfg(feature = "redis-cache")]
pub use redis_cache::*;

#[cfg(feature = "redis-cache")]
mod redis_cache {
    use super::{Cache, Error, Result};
    use crate::macros::on_error;
    use async_trait::async_trait;
    use reool::{AsyncCommands, PoolDefault, RedisError, RedisPool};
    use serde::{de::DeserializeOwned, Serialize};
    use std::fmt::Debug;
    use std::num::TryFromIntError;
    use std::time::Duration;

    /// Redis implementation of [`Cache`].
    pub struct RedisCache<'a> {
        pub pool: &'a RedisPool,
    }

    #[async_trait]
    impl<'a> Cache for RedisCache<'a> {
        #[instrument(skip(self))]
        async fn find<T>(&self, key: &str) -> Result<T>
        where
            T: DeserializeOwned,
        {
            let mut conn = self
                .pool
                .check_out(PoolDefault)
                .await
                .map_err(on_error!(Error, "pulling connection for redis"))?;

            let Some(data): Option<String> = conn
                .get(key)
                .await
                .map_err(on_error!(Error, "performing GET command on redis"))?
            else {
                return Error::NotFound.into();
            };

            serde_json::from_str(&data).map_err(on_error!(Error, "deserializing data from redis"))
        }

        #[instrument(skip(self))]
        async fn save<T>(&self, key: &str, value: T, expire: Duration) -> Result<()>
        where
            T: Serialize + Send + Sync + Debug,
        {
            let mut conn = self
                .pool
                .check_out(PoolDefault)
                .await
                .map_err(on_error!(Error, "pulling connection for redis"))?;

            let data = serde_json::to_string(&value)
                .map_err(on_error!(Error, "serializing data for redis"))?;

            conn.set(key, data)
                .await
                .map_err(on_error!(Error, "performing SET command on redis"))?;

            let expire = expire.as_secs().try_into().map_err(on_error!(
                TryFromIntError as Error,
                "parsing expiration time to usize"
            ))?;

            conn.expire(key, expire)
                .await
                .map_err(on_error!(Error, "performing EXPIRE command on redis"))?;

            Ok(())
        }

        #[instrument(skip(self))]
        async fn delete(&self, key: &str) -> Result<()> {
            let mut conn = self
                .pool
                .check_out(PoolDefault)
                .await
                .map_err(RedisError::from)
                .map_err(on_error!(Error, "pulling connection for redis"))?;

            conn.del(key)
                .await
                .map_err(RedisError::from)
                .map_err(on_error!(Error, "performing DELETE command on redis"))?;

            Ok(())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{Cache, Error, Result};
    use crate::macros::on_error;
    use async_trait::async_trait;
    use serde::{de::DeserializeOwned, Serialize};
    use std::fmt::Debug;
    use std::time::Duration;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    pub type DeleteFn = fn(key: &str) -> Result<()>;

    /// In memory implementation of [`Cache`].
    pub struct InMemoryCache {
        pub values: Arc<Mutex<HashMap<String, String>>>,
        pub delete_fn: Option<DeleteFn>,
    }

    impl Default for InMemoryCache {
        fn default() -> Self {
            Self {
                values: Arc::new(Mutex::new(HashMap::new())),
                delete_fn: Default::default(),
            }
        }
    }

    #[async_trait]
    impl Cache for InMemoryCache {
        async fn find<T>(&self, key: &str) -> Result<T>
        where
            T: DeserializeOwned,
        {
            let Some(data) = self
                .values
                .lock()
                .unwrap()
                .get(key)
                .map(ToString::to_string)
            else {
                return Error::NotFound.into();
            };

            serde_json::from_str(&data).map_err(on_error!(Error, "deserializing data from json"))
        }

        async fn save<T>(&self, key: &str, value: T, _expire: Duration) -> Result<()>
        where
            T: Serialize + Send + Sync + Debug,
        {
            let data = serde_json::to_string(&value)
                .map_err(on_error!(Error, "serializing data to json"))?;

            self.values.lock().unwrap().insert(key.to_string(), data);

            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<()> {
            if let Some(delete_fn) = self.delete_fn {
                return delete_fn(key);
            }

            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }
}
