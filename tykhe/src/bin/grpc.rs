#[macro_use]
extern crate tracing;

use jsonwebtoken::{DecodingKey, EncodingKey};
use std::sync::Arc;
use std::time::Duration;
use std::{error::Error, net::SocketAddr};
use tera::Tera;
use tonic::transport::Server;
use tykhe::{
    cache::RedisCache,
    config,
    multi_factor::{
        domain::MultiFactorMethod,
        service::MultiFactor,
        smtp::MultiFactorSmtp,
        strategy::{EmailMethod, ThirdPartyAppMethod},
    },
    postgres, redis,
    secret::repository::PostgresSecretRepository,
    session::{
        application::SessionApplication,
        grpc::{SessionGrpcService, SessionServer},
    },
    smtp,
    smtp::SmtpBuilder,
    token::service::JsonWebTokenService,
    tracer,
    user::{
        application::UserApplication,
        grpc::{UserGrpcService, UserServer},
        repository::PostgresUserRepository,
        smtp::UserSmtp,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if let Err(err) = dotenv::dotenv() {
        warn!(error = err.to_string(), "processing dotenv file");
    }

    tracer::init()?;

    let secret_repo = Arc::new(PostgresSecretRepository {
        pool: &postgres::POSTGRES_POOL,
    });

    let user_repo = Arc::new(PostgresUserRepository {
        pool: &postgres::POSTGRES_POOL,
    });

    let cache = Arc::new(RedisCache {
        pool: &redis::REDIS_POOL,
    });

    let smtp = Arc::new(
        SmtpBuilder {
            issuer: &smtp::SMTP_ISSUER,
            origin: &smtp::SMTP_ORIGIN,
            transport: &smtp::SMTP_TRANSPORT,
            username: &smtp::SMTP_USERNAME,
            password: &smtp::SMTP_PASSWORD,
        }
        .build()?,
    );

    let token_srv = Arc::new(JsonWebTokenService {
        session_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        verification_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        reset_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
        issuer: &config::TOKEN_ISSUER,
        encode: EncodingKey::from_ec_pem(&config::JWT_SECRET)?,
        decode: DecodingKey::from_ec_pem(&config::JWT_PUBLIC)?,
        cache: cache.clone(),
    });

    let mut multi_factor_srv = MultiFactor::default();
    multi_factor_srv.methods.insert(
        MultiFactorMethod::TpApp,
        Box::new(ThirdPartyAppMethod {
            ack_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
            totp_secret_len: *config::TOTP_SECRET_LEN,
            secret_repo: secret_repo.clone(),
            cache: cache.clone(),
        }),
    );

    let tera = Arc::new(Tera::new(&smtp::SMTP_TEMPLATES)?);

    let multi_factor_mail_srv = Arc::new(MultiFactorSmtp {
        smtp: smtp.clone(),
        tera: tera.clone(),
        otp_subject: "",
        otp_template: "",
    });

    multi_factor_srv.methods.insert(
        MultiFactorMethod::Email,
        Box::new(EmailMethod {
            otp_timeout: Duration::from_secs(*config::TOKEN_TIMEOUT),
            otp_length: *config::TOTP_SECRET_LEN,
            mail_srv: multi_factor_mail_srv,
            cache: cache.clone(),
        }),
    );

    let multi_factor_srv = Arc::new(multi_factor_srv);

    let user_smtp = Arc::new(UserSmtp {
        smtp: smtp.clone(),
        tera: tera.clone(),
        verification_subject: "",
        verification_template: "",
        reset_subject: "",
        reset_template: "",
    });

    let user_app = UserApplication {
        hash_length: 32,
        user_repo: user_repo.clone(),
        secret_repo: secret_repo.clone(),
        token_srv: token_srv.clone(),
        mail_srv: user_smtp.clone(),
        multi_factor_srv: multi_factor_srv.clone(),
        cache: cache.clone(),
    };

    let user_grpc_service = UserGrpcService {
        user_app,
        jwt_header: &config::JWT_HEADER,
        totp_header: &config::TOTP_HEADER,
    };

    let session_app = SessionApplication {
        user_repo: user_repo.clone(),
        secret_repo: secret_repo.clone(),
        multi_factor_srv: multi_factor_srv.clone(),
        token_srv: token_srv.clone(),
    };

    let session_grpc_service = SessionGrpcService {
        session_app,
        jwt_header: &config::JWT_HEADER,
    };

    let addr: SocketAddr = config::SERVICE_ADDR.parse()?;
    info!(
        address = addr.to_string(),
        "server ready to accept connections"
    );

    Server::builder()
        .add_service(UserServer::new(user_grpc_service))
        .add_service(SessionServer::new(session_grpc_service))
        .serve(addr)
        .await
        .unwrap();

    tracer::shutdown();
    Ok(())
}
