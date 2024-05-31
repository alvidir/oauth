use super::{
    domain::{Claims, Payload, Token, TokenKind},
    error::{Error, Result},
};
use crate::{cache::Cache, macros::on_error};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation};
use std::{sync::Arc, time::Duration};

#[async_trait]
pub trait TokenService {
    /// Issues a new token of the given kind for the given user.
    async fn issue(&self, kind: TokenKind, sub: &str) -> Result<Claims>;
    /// Returns the claims of the given token if, and only if, the token is valid.
    async fn claims(&self, token: Token) -> Result<Claims>;
    /// Invalidates the token associated to the given payload, if any.
    async fn revoke(&self, claims: &Claims) -> Result<()>;
}

/// Implements the [TokenService] trait.
pub struct JsonWebTokenService<'a, C> {
    pub issuer: &'a str,
    pub session_timeout: Duration,
    pub verification_timeout: Duration,
    pub reset_timeout: Duration,
    pub decode: DecodingKey,
    pub encode: EncodingKey,
    pub cache: Arc<C>,
}

#[async_trait]
impl<'a, C> TokenService for JsonWebTokenService<'a, C>
where
    C: Cache + Send + Sync,
{
    #[instrument(skip(self))]
    async fn issue(&self, kind: TokenKind, subject: &str) -> Result<Claims> {
        let timeout = match kind {
            TokenKind::Session => self.session_timeout,
            TokenKind::Verification => self.verification_timeout,
            TokenKind::Reset => self.reset_timeout,
        };

        let payload = Payload::new(TokenKind::Verification, timeout)
            .with_issuer(self.issuer)
            .with_subject(subject);

        let id = payload.hash().to_string();
        let payload = payload.with_id(id);
        let token = self.encode(&payload)?;

        self.store(&payload).await?;
        Ok(Claims { token, payload })
    }

    #[instrument(skip(self))]
    async fn claims(&self, token: Token) -> Result<Claims> {
        let payload = self.decode(&token)?;

        let Some(actual_payload) = self.find(&payload.jti).await? else {
            return Error::RejectedToken.into();
        };

        if payload != actual_payload {
            return Error::Collision.into();
        }

        Ok(Claims { token, payload })
    }

    #[instrument(skip(self))]
    async fn revoke(&self, claims: &Claims) -> Result<()> {
        self.cache
            .delete(&claims.payload().jti)
            .await
            .map_err(Into::into)
    }
}

impl<'a, C> JsonWebTokenService<'a, C>
where
    C: Cache,
{
    /// Returns the resulting token of signing and encoding the given payload.
    #[instrument(skip(self))]
    fn encode(&self, payload: &Payload) -> Result<Token> {
        let header = Header::new(JwtAlgorithm::ES256);

        jsonwebtoken::encode(&header, payload, &self.encode)
            .map_err(on_error!(Error, "encoding payload into a token"))
            .and_then(Token::try_from)
    }

    /// Returns the payload of the given token.
    #[instrument(skip(self))]
    fn decode(&self, token: &Token) -> Result<Payload> {
        let mut validation = Validation::new(JwtAlgorithm::ES256);
        validation.set_required_spec_claims(&["jti", "sub", "iss", "knd"]);
        validation.set_issuer(&[self.issuer]);

        jsonwebtoken::decode(token.as_ref(), &self.decode, &validation)
            .map(|token| token.claims)
            .map_err(on_error!(Error, "decoding payload from token"))
    }

    /// Stores the given [Payload] in the cache.
    #[instrument(skip(self))]
    async fn store(&self, payload: &Payload) -> Result<()> {
        self.cache
            .save(&payload.jti, payload, payload.timeout())
            .await
            .map_err(Into::into)
    }

    /// Retrives the [Payload] associated to the given token ID, if any.
    #[instrument(skip(self))]
    async fn find(&self, id: &str) -> Result<Option<Payload>> {
        self.cache.find(id).await.map_err(Into::into)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use async_trait::async_trait;

    use super::TokenService;
    use crate::token::domain::{Claims, Token, TokenKind};
    use crate::token::error::{Error, Result};

    pub type IssueFn = fn(kind: TokenKind, sub: &str) -> Result<Claims>;
    pub type ClaimsFn = fn(token: Token) -> Result<Claims>;
    pub type RevokeFn = fn(claims: &Claims) -> Result<()>;

    #[derive(Debug, Default)]
    pub struct TokenServiceMock {
        pub issue_fn: Option<IssueFn>,
        pub claims_fn: Option<ClaimsFn>,
        pub revoke_fn: Option<RevokeFn>,
    }

    #[async_trait]
    impl TokenService for TokenServiceMock {
        async fn issue(&self, kind: TokenKind, sub: &str) -> Result<Claims> {
            if let Some(issue_fn) = self.issue_fn {
                return issue_fn(kind, sub);
            }

            Err(Error::Debug)
        }
        async fn claims(&self, token: Token) -> Result<Claims> {
            if let Some(claims_fn) = self.claims_fn {
                return claims_fn(token);
            }

            Err(Error::Debug)
        }
        async fn revoke(&self, claims: &Claims) -> Result<()> {
            if let Some(revoke_fn) = self.revoke_fn {
                return revoke_fn(claims);
            }

            Err(Error::Debug)
        }
    }
}

// #[cfg(test)]
// pub mod tests {
// use super::JsonWebTokenService;
// use crate::cache::tests::InMemoryCache;
// use crate::token::domain::{Token, TokenKind};
// use crate::token::error::Error;
// use base64::{engine::general_purpose, Engine as _};
// use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};
// use jsonwebtoken::{DecodingKey, EncodingKey};
// use once_cell::sync::Lazy;
// use std::sync::Arc;
// use std::time::{Duration, SystemTime};

// pub static PRIVATE_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
//     general_purpose::STANDARD.decode(
//         b"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZy9JMGJTbVZxL1BBN2FhRHgKN1FFSGdoTGxCVS9NcWFWMUJab3ZhM2Y5aHJxaFJBTkNBQVJXZVcwd3MydmlnWi96SzRXcGk3Rm1mK0VPb3FybQpmUlIrZjF2azZ5dnBGd0gzZllkMlllNXl4b3ZsaTROK1ZNNlRXVFErTmVFc2ZmTWY2TkFBMloxbQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
//     ).unwrap()
// });

// pub static PUBLIC_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
//     general_purpose::STANDARD.decode(
//         b"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVm5sdE1MTnI0b0dmOHl1RnFZdXhabi9oRHFLcQo1bjBVZm45YjVPc3I2UmNCOTMySGRtSHVjc2FMNVl1RGZsVE9rMWswUGpYaExIM3pIK2pRQU5tZFpnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
//     ).unwrap()
// });

// pub const TEST_TOKEN_TIMEOUT: u64 = 60;
// pub const TEST_TOKEN_ISSUER: &str = "test";
// pub const TEST_TOKEN_SUBJECT: &str = "999";

// pub fn new_token_srvlication<'a>() -> JsonWebTokenService<'a, InMemoryCache> {
//     JsonWebTokenService {
//         issuer: "test",
//         session_timeout: Duration::from_secs(TEST_TOKEN_TIMEOUT),
//         verification_timeout: Duration::from_secs(TEST_TOKEN_TIMEOUT),
//         reset_timeout: Duration::from_secs(TEST_TOKEN_TIMEOUT),
//         decode: DecodingKey::from_ec_pem(&PUBLIC_KEY).unwrap(),
//         encode: EncodingKey::from_ec_pem(&PRIVATE_KEY).unwrap(),
//         cache: Arc::new(InMemoryCache),
//     }
// }

// #[tokio::test]
// async fn consume_token_should_not_fail() {
//     let app = new_token_srvlication();
//     let payload = app.new_payload(TokenKind::Session, TEST_TOKEN_SUBJECT);
//     let token = app.issue(payload).await.unwrap();

//     let claims = app.consume(TokenKind::Session, token).await.unwrap();
//     assert!(matches!(&claims.knd, TokenKind::Session));
// }

// #[tokio::test]
// async fn consume_expired_token_should_fail() {
//     let app = new_token_srvlication();
//     let mut payload = app.new_payload(TokenKind::Session, TEST_TOKEN_SUBJECT);
//     payload.exp = SystemTime::now() - Duration::from_secs(61);

//     let token = app.encode(&payload).unwrap();

//     app.consume(TokenKind::Session, token)
//         .await
//         .map_err(|err| {
//             let want: Error = JwtError::from(JwtErrorKind::ExpiredSignature).into();
//             assert!(matches!(err, want))
//         })
//         .unwrap_err();
// }

// #[tokio::test]
// async fn consume_corrupt_token_should_fail() {
//     let app = new_token_srvlication();
//     let payload = app.new_payload(TokenKind::Session, TEST_TOKEN_SUBJECT);
//     let token = app.issue(payload).await.unwrap();
//     let corrupted: Token = token.as_ref().replace('A', "a").try_into().unwrap();

//     let err = app
//         .consume(TokenKind::Session, corrupted)
//         .await
//         .unwrap_err();
//     assert!(matches!(err, Error::Jwt(_)));
// }

// #[tokio::test]
// async fn consume_wrong_token_kind_should_fail() {
//     let app = new_token_srvlication();
//     let payload = app.new_payload(TokenKind::Session, TEST_TOKEN_SUBJECT);
//     let token = app.issue(payload).await.unwrap();

//     let err = app
//         .consume(TokenKind::Verification, token)
//         .await
//         .unwrap_err();
//     assert!(matches!(err, Error::Jwt(_)));
// }
// }
