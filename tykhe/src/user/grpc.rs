use super::application::MailService;
use super::domain::Password;
use super::error::Error;
use crate::cache::Cache;
use crate::grpc;
use crate::macros::on_error;
use crate::multi_factor::domain::MultiFactorMethod;
use crate::multi_factor::service::MultiFactorService;
use crate::secret::service::SecretRepository;
use crate::token::domain::Token;
use crate::token::service::TokenService;
use crate::user::application::{UserApplication, UserRepository};
use std::ops::Not;
use std::str::FromStr;
use tonic::metadata::errors::InvalidMetadataValue;
use tonic::{Request, Response, Status};

// Import the generated rust code into module
mod proto {
    tonic::include_proto!("user");
}

// Proto generated server traits
use proto::user_server::User;
pub use proto::user_server::UserServer;

// Proto message structs
use proto::{
    multi_factor_request::Actions, DeleteRequest, Empty, MultiFactorRequest, ResetPasswordRequest,
    SignupRequest,
};

pub struct UserGrpcService<U, S, T, F, M, C> {
    pub user_app: UserApplication<U, S, T, F, M, C>,
    pub jwt_header: &'static str,
    pub totp_header: &'static str,
}

#[tonic::async_trait]
impl<U, S, T, F, M, C> User for UserGrpcService<U, S, T, F, M, C>
where
    U: 'static + UserRepository + Sync + Send,
    S: 'static + SecretRepository + Sync + Send,
    T: 'static + TokenService + Sync + Send,
    F: 'static + MultiFactorService + Sync + Send,
    M: 'static + MailService + Sync + Send,
    C: 'static + Cache + Sync + Send,
{
    #[instrument(skip(self))]
    async fn signup(&self, request: Request<SignupRequest>) -> Result<Response<Empty>, Status> {
        let token = grpc::header(&request, self.jwt_header)
            .map_err(Status::from)?
            .map(Token::try_from)
            .transpose()?;

        let request = request.into_inner();
        let password = Some(request.password)
            .filter(|s| !s.is_empty())
            .map(Password::try_from)
            .transpose()?;

        let Some(token) = token else {
            let email = request.email.try_into()?;
            return self
                .user_app
                .verify_credentials(email, password)
                .await
                .map(|_| Response::new(Empty {}))
                .map_err(Status::from);
        };

        let session_token = self
            .user_app
            .signup_with_token(token, password)
            .await
            .map_err(Status::from)?;

        let mut res = Response::new(Empty {});
        let token = session_token.token.as_ref().parse().map_err(on_error!(
            InvalidMetadataValue as Error,
            "parsing token to header"
        ))?;

        res.metadata_mut().append(self.jwt_header, token);
        Ok(res)
    }

    #[instrument(skip(self))]
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<Empty>, Status> {
        let Some(header) = grpc::header(&request, self.jwt_header).map_err(Status::from)? else {
            let request = request.into_inner();
            let email = request.email.try_into().map_err(Status::from)?;

            return self
                .user_app
                .confirm_password_reset(email)
                .await
                .map(|_| Response::new(Empty {}))
                .map_err(Status::from);
        };

        let request = request.into_inner();
        let token = header.try_into().map_err(Status::from)?;
        let new_password = request.new_password.try_into().map_err(Status::from)?;
        let otp = request
            .otp
            .is_empty()
            .not()
            .then_some(request.otp.to_string())
            .map(TryInto::try_into)
            .transpose()
            .map_err(Status::from)?;

        self.user_app
            .reset_password_with_token(token, new_password, otp)
            .await
            .map(|_| Response::new(Empty {}))
            .map_err(Status::from)
    }

    #[instrument(skip(self))]
    async fn delete(&self, request: Request<DeleteRequest>) -> Result<Response<Empty>, Status> {
        let Some(header) = grpc::header(&request, self.jwt_header).map_err(Status::from)? else {
            return Err(Error::Forbidden).map_err(Into::into);
        };

        let request = request.into_inner();
        let token = header.try_into().map_err(Status::from)?;
        let password = request.password.try_into().map_err(Status::from)?;
        let otp = request
            .otp
            .is_empty()
            .not()
            .then_some(request.otp.to_string())
            .map(TryInto::try_into)
            .transpose()
            .map_err(Status::from)?;

        self.user_app
            .delete_with_token(token, password, otp)
            .await
            .map(|_| Response::new(Empty {}))
            .map_err(|err| Status::aborted(err.to_string()))
    }

    #[instrument(skip(self))]
    async fn multi_factor(
        &self,
        request: Request<MultiFactorRequest>,
    ) -> Result<Response<Empty>, Status> {
        let Some(header) = grpc::header(&request, self.jwt_header).map_err(Status::from)? else {
            return Err(Error::Forbidden).map_err(Into::into);
        };

        let request = request.into_inner();
        let token = header.try_into().map_err(Status::from)?;
        let password = request.password.try_into().map_err(Status::from)?;
        let otp = request
            .otp
            .is_empty()
            .not()
            .then_some(request.otp.to_string())
            .map(TryInto::try_into)
            .transpose()
            .map_err(Status::from)?;

        let method = MultiFactorMethod::from_str(&request.method)?;
        match Actions::try_from(request.action).map_err(|_| Status::invalid_argument("action"))? {
            Actions::Enable => {
                self.user_app
                    .enable_multi_factor_with_token(token, method, password, otp)
                    .await
            }
            Actions::Disable => {
                self.user_app
                    .disable_multi_factor_with_token(token, method, password, otp)
                    .await
            }
        }
        .map(|_| Response::new(Empty {}))
        .map_err(Into::into)
    }
}
