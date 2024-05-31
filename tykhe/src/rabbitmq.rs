//! RabbitMQ utilities for managing events handlering and emitions.

use crate::config;
use deadpool_lapin::{Config, Pool, Runtime, Timeouts};
use lapin::{options, types::FieldTable, ExchangeKind};
use once_cell::sync::Lazy;
use std::env;
use std::time::Duration;

const ENV_RABBITMQ_USERS_EXCHANGE: &str = "RABBITMQ_USERS_EXCHANGE";
const ENV_RABBITMQ_TIMEOUT: &str = "RABBITMQ_TIMEOUT";
const ENV_RABBITMQ_URL: &str = "RABBITMQ_URL";
const ENV_RABBITMQ_POOL: &str = "RABBITMQ_POOL";
const ENV_EVENT_ISSUER: &str = "EVENT_ISSUER";

pub static RABBITMQ_USERS_EXCHANGE: Lazy<String> = Lazy::new(|| {
    env::var(ENV_RABBITMQ_USERS_EXCHANGE).expect("rabbitmq users bus name must be set")
});

pub static RABBITMQ_TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    Duration::from_millis(
        env::var(ENV_RABBITMQ_TIMEOUT)
            .unwrap_or(config::DEFAULT_CONN_TIMEOUT.to_string())
            .parse()
            .expect("timeout must be an unsigned number of seconds"),
    )
});

pub static RABBITMQ_POOL: Lazy<Pool> = Lazy::new(|| {
    futures::executor::block_on(async {
        let rabbitmq_url = env::var(ENV_RABBITMQ_URL).expect("rabbitmq url must be set");
        let rabbitmq_pool = env::var(ENV_RABBITMQ_POOL)
            .map(|pool_size| pool_size.parse().unwrap())
            .unwrap_or_else(|_| config::DEFAULT_POOL_SIZE.try_into().unwrap());

        let pool = Config {
            url: Some(rabbitmq_url),
            ..Default::default()
        }
        .builder(Some(Runtime::Tokio1))
        .max_size(rabbitmq_pool)
        .timeouts(Timeouts {
            wait: Some(*RABBITMQ_TIMEOUT),
            create: Some(*RABBITMQ_TIMEOUT),
            recycle: Some(*RABBITMQ_TIMEOUT),
        })
        .build()
        .unwrap();

        let channel = pool.get().await.unwrap().create_channel().await.unwrap();

        let exchange_options = options::ExchangeDeclareOptions {
            durable: true,
            auto_delete: false,
            internal: false,
            nowait: false,
            passive: false,
        };

        channel
            .exchange_declare(
                &RABBITMQ_USERS_EXCHANGE,
                ExchangeKind::Fanout,
                exchange_options,
                FieldTable::default(),
            )
            .await
            .unwrap();

        pool
    })
});

pub static EVENT_ISSUER: Lazy<String> =
    Lazy::new(|| env::var(ENV_EVENT_ISSUER).expect("event issuer must be set"));
