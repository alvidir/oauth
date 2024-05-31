use crate::config;
use once_cell::sync::Lazy;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{env, time::Duration};

const ENV_POSTGRES_TIMEOUT: &str = "POSTGRES_TIMEOUT";
const ENV_POSTGRES_DSN: &str = "POSTGRES_DSN";
const ENV_POSTGRES_POOL: &str = "POSTGRES_POOL";

pub static POSTGRES_TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    Duration::from_millis(
        env::var(ENV_POSTGRES_TIMEOUT)
            .unwrap_or(config::DEFAULT_CONN_TIMEOUT.to_string())
            .parse()
            .expect("timeout must be an unsigned number of seconds"),
    )
});

pub static POSTGRES_POOL: Lazy<PgPool> = Lazy::new(|| {
    futures::executor::block_on(async {
        let postgres_dsn = env::var(ENV_POSTGRES_DSN).expect("postgres dns must be set");

        let postgres_pool = env::var(ENV_POSTGRES_POOL)
            .map(|pool_size| pool_size.parse().unwrap())
            .unwrap_or(config::DEFAULT_POOL_SIZE);

        PgPoolOptions::new()
            .max_connections(postgres_pool)
            .acquire_timeout(*POSTGRES_TIMEOUT)
            .connect(&postgres_dsn)
            .await
            .unwrap()
    })
});

macro_rules! on_query_error {
    ($msg:tt) => {
        |error| {
            if matches!(error, SqlError::RowNotFound) {
                return Error::NotFound;
            }

            error!(error = error.to_string(), $msg,);
            error.into()
        }
    };
}

pub(crate) use on_query_error;
