use std::ops::Not;

use super::application::SessionApplication;
use super::error::Error;
use crate::grpc;
use crate::macros::on_error;
use crate::multi_factor::service::MultiFactorService;
use crate::secret::service::SecretRepository;
use crate::token::service::TokenService;
use crate::user::application::UserRepository;
use tonic::metadata::errors::InvalidMetadataValue;
use tonic::{Request, Response, Status};

// Import the generated rust code into module
mod proto {
    tonic::include_proto!("session");
}

// Proto generated server traits
use proto::session_server::Session;
pub use proto::session_server::SessionServer;

// Proto message structs
use proto::{Empty, LoginRequest};

pub struct SessionGrpcService<U, S, T, F> {
    pub session_app: SessionApplication<U, S, T, F>,
    pub jwt_header: &'static str,
}

#[tonic::async_trait]
impl<U, S, T, F> Session for SessionGrpcService<U, S, T, F>
where
    U: 'static + UserRepository + Sync + Send,
    S: 'static + SecretRepository + Sync + Send,
    T: 'static + TokenService + Sync + Send,
    F: 'static + MultiFactorService + Sync + Send,
{
    #[instrument(skip(self))]
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<Empty>, Status> {
        let request = request.into_inner();
        let identity = request.identifier.try_into().map_err(Status::from)?;
        let password = request.password.try_into().map_err(Status::from)?;
        let otp = request
            .otp
            .is_empty()
            .not()
            .then_some(request.otp.to_string())
            .map(TryInto::try_into)
            .transpose()
            .map_err(Status::from)?;

        let claims = self
            .session_app
            .login(identity, password, otp)
            .await
            .map_err(Status::from)?;

        let mut res = Response::new(Empty {});
        let token = claims
            .token
            .as_ref()
            .parse()
            .map_err(on_error!(
                InvalidMetadataValue as Error,
                "parsing token to header"
            ))
            .map_err(Status::from)?;

        res.metadata_mut().append(self.jwt_header, token);
        Ok(res)
    }

    #[instrument(skip(self))]
    async fn logout(&self, request: Request<Empty>) -> Result<Response<Empty>, Status> {
        let Some(header) = grpc::header(&request, self.jwt_header).map_err(Status::from)? else {
            return Err(Error::Forbidden).map_err(Into::into);
        };

        let token = header.try_into().map_err(Status::from)?;
        self.session_app
            .logout(token)
            .await
            .map_err(Into::into)
            .map(|_| Response::new(Empty {}))
    }
}
