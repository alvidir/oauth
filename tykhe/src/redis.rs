use crate::config;
use once_cell::sync::Lazy;
use reool::{config::DefaultCommandTimeout, RedisPool};
use std::env;
use tokio::runtime::Handle;

const ENV_REDIS_TIMEOUT: &str = "REDIS_TIMEOUT";
const ENV_REDIS_URL: &str = "REDIS_URL";
const ENV_REDIS_POOL: &str = "REDIS_POOL";

pub static REDIS_TIMEOUT: Lazy<DefaultCommandTimeout> = Lazy::new(|| {
    env::var(ENV_REDIS_TIMEOUT)
        .unwrap_or(config::DEFAULT_CONN_TIMEOUT.to_string())
        .parse()
        .unwrap()
});

pub static REDIS_POOL: Lazy<RedisPool> = Lazy::new(|| {
    let redis_url: String = env::var(ENV_REDIS_URL).expect("redis url must be set");
    let redis_pool: usize = env::var(ENV_REDIS_POOL)
        .map(|pool_size| pool_size.parse().unwrap())
        .unwrap_or_else(|_| config::DEFAULT_POOL_SIZE.try_into().unwrap());

    RedisPool::builder()
        .connect_to_node(redis_url)
        .desired_pool_size(redis_pool)
        .task_executor(Handle::current())
        .default_command_timeout(*REDIS_TIMEOUT)
        .finish_redis_rs()
        .unwrap()
});
