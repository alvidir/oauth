#[macro_use]
extern crate tracing;

use axum::http::{HeaderName, HeaderValue};
use axum::Router;
use axum_extra::headers::Header;
use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use std::error::Error;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tykhe::cache::RedisCache;
use tykhe::token::domain::Token;
use tykhe::{
    config, redis,
    token::{
        rest::{TokenHeader, TokenRestService},
        service::JsonWebTokenService,
    },
    tracer,
};

static TOKEN_HEADER_NAME: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_str(&config::JWT_HEADER).unwrap());

struct JwtTokenHeader(Token);

impl Header for JwtTokenHeader {
    fn name() -> &'static axum::http::HeaderName {
        &TOKEN_HEADER_NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i axum::http::HeaderValue>,
    {
        let Some(header_value) = values.into_iter().next() else {
            return Err(axum_extra::headers::Error::invalid());
        };

        if values.into_iter().next().is_some() {
            return Err(axum_extra::headers::Error::invalid());
        };

        let header_value = match header_value.to_owned().to_str() {
            Ok(header_value) => header_value.to_string(),
            Err(error) => {
                error!(error = error.to_string(), "parsing header value into str");
                return Err(axum_extra::headers::Error::invalid());
            }
        };

        Token::try_from(header_value)
            .map(JwtTokenHeader)
            .map_err(|_| axum_extra::headers::Error::invalid())
    }

    fn encode<E: Extend<axum::http::HeaderValue>>(&self, values: &mut E) {
        if let Ok(header_value) = HeaderValue::from_str(self.0.as_ref()) {
            values.extend(vec![header_value].into_iter());
        }
    }
}

impl TokenHeader for JwtTokenHeader {
    fn token(self) -> Token {
        self.0
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if let Err(err) = dotenv::dotenv() {
        warn!(error = err.to_string(), "processing dotenv file",);
    }

    tracer::init()?;

    let cache = Arc::new(RedisCache {
        pool: &redis::REDIS_POOL,
    });

    let token_srv = Arc::new(JsonWebTokenService {
        session_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        verification_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        reset_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        issuer: &config::TOKEN_ISSUER,
        encode: EncodingKey::from_ec_pem(&config::JWT_SECRET)?,
        decode: DecodingKey::from_ec_pem(&config::JWT_PUBLIC)?,
        cache,
    });

    let token_server = Arc::new(TokenRestService {
        token_srv,
        token_header: PhantomData::<JwtTokenHeader>,
    });

    let app = token_server.router(Router::new()).with_state(token_server);

    info!(
        address = *config::SERVICE_ADDR,
        "server ready to accept connections"
    );

    let listener = tokio::net::TcpListener::bind(&*config::SERVICE_ADDR)
        .await
        .unwrap();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();

    tracer::shutdown();
    Ok(())
}
