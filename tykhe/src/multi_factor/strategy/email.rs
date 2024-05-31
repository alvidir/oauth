use crate::{
    cache::Cache,
    multi_factor::{
        domain::Otp,
        error::{Error, Result},
        service::MultiFactorService,
    },
    user::domain::{Email, User},
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// Represents the mail service contract required by the multi factor email methods.
pub trait MailService {
    fn send_otp_email(&self, to: &Email, token: &Otp) -> Result<()>;
}

/// Implements the [MultiFactorService] for the email method.
pub struct EmailMethod<M, C> {
    pub otp_timeout: Duration,
    pub otp_length: usize,
    pub mail_srv: Arc<M>,
    pub cache: Arc<C>,
}

#[async_trait]
impl<M, C> MultiFactorService for EmailMethod<M, C>
where
    M: MailService + Sync + Send,
    C: Cache + Sync + Send,
{
    async fn verify(&self, user: &User, otp: Option<&Otp>) -> Result<()> {
        let actual_otp = match self
            .cache
            .find::<Otp>(&Self::key(user))
            .await
            .map(Option::Some)
        {
            Err(err) if err.is_not_found() => Ok(None),
            other => other,
        }
        .map_err(Error::from)?;

        let Some(actual_otp) = actual_otp else {
            let otp = self.issue_otp(user, self.otp_length).await?;
            self.mail_srv
                .send_otp_email(&user.credentials.email, &otp)?;

            return Err(Error::Required);
        };

        let otp = otp.ok_or(Error::Required)?;
        if otp == &actual_otp {
            return self
                .cache
                .delete(&user.id.to_string())
                .await
                .map_err(Error::from);
        }

        Err(Error::Invalid)
    }

    async fn enable(&self, user: &User, otp: Option<&Otp>) -> Result<()> {
        self.verify(user, otp).await
    }

    async fn disable(&self, user: &User, otp: Option<&Otp>) -> Result<()> {
        self.verify(user, otp).await
    }
}

impl<M, C> EmailMethod<M, C>
where
    M: MailService + Sync + Send,
    C: Cache + Sync + Send,
{
    async fn issue_otp(&self, user: &User, len: usize) -> Result<Otp> {
        let otp = Otp::with_length(len)?;
        self.cache
            .save(&Self::key(user), &otp, self.otp_timeout)
            .await
            .map(|_| otp)
            .map_err(Into::into)
    }
}

impl<M, C> EmailMethod<M, C> {
    fn key(user: &User) -> String {
        [&user.id.to_string(), "otp"].join("::")
    }
}
