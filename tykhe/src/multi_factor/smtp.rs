use std::sync::Arc;

use super::{
    domain::Otp,
    error::{Error, Result},
    strategy::MailService,
};
use crate::{macros::on_error, smtp::Smtp, user::domain::Email};
use tera::{Context, Tera};

/// Implements the [MailService] trait.
pub struct MultiFactorSmtp<'a> {
    pub smtp: Arc<Smtp<'a>>,
    pub tera: Arc<Tera>,
    pub otp_subject: &'a str,
    pub otp_template: &'a str,
}

impl<'a> MailService for MultiFactorSmtp<'a> {
    #[instrument(skip(self))]
    fn send_otp_email(&self, email: &Email, otp: &Otp) -> Result<()> {
        let mut context = Context::new();
        context.insert("name", email.username());
        context.insert("otp", otp.as_ref());

        let body = self
            .tera
            .render(self.otp_template, &context)
            .map_err(on_error!(Error, "rendering otp email template"))?;

        self.smtp
            .send(email, self.otp_subject, &body)
            .map_err(Into::into)
    }
}
