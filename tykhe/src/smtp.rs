//! Smtp implementation for sending of predefined email templates.

use crate::macros::on_error;
use crate::user::domain::Email;
use lettre::address::AddressError;
use lettre::message::{Mailbox, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::Tls;
use lettre::{Message, SmtpTransport, Transport};
use once_cell::sync::Lazy;
use std::env;
use std::num::ParseIntError;

const DEFAULT_TEMPLATES_PATH: &str = "/etc/tykhe/smtp/templates/*.html";
const DEFAULT_VERIFICATION_SUBJECT: &str = "Email verification";
const DEFAULT_VERIFICATION_TEMPLATE: &str = "verification_email.html";
const DEFAULT_RESET_SUBJECT: &str = "Reset password";
const DEFAULT_RESET_TEMPLATE: &str = "reset_email.html";

const ENV_SMTP_TRANSPORT: &str = "SMTP_TRANSPORT";
const ENV_SMTP_USERNAME: &str = "SMTP_USERNAME";
const ENV_SMTP_PASSWORD: &str = "SMTP_PASSWORD";
const ENV_SMTP_ISSUER: &str = "SMTP_ISSUER";
const ENV_SMTP_TEMPLATES: &str = "SMTP_TEMPLATES";
const ENV_SMTP_ORIGIN: &str = "SMTP_ORIGIN";

pub static SMTP_TRANSPORT: Lazy<String> =
    Lazy::new(|| env::var(ENV_SMTP_TRANSPORT).expect("smtp transport must be set"));

pub static SMTP_USERNAME: Lazy<String> =
    Lazy::new(|| env::var(ENV_SMTP_USERNAME).unwrap_or_default());

pub static SMTP_PASSWORD: Lazy<String> =
    Lazy::new(|| env::var(ENV_SMTP_PASSWORD).unwrap_or_default());

pub static SMTP_ORIGIN: Lazy<String> =
    Lazy::new(|| env::var(ENV_SMTP_ORIGIN).expect("smpt origin must be set"));

pub static SMTP_ISSUER: Lazy<String> =
    Lazy::new(|| env::var(ENV_SMTP_ISSUER).expect("smtp issuer must be set"));

pub static SMTP_TEMPLATES: Lazy<String> = Lazy::new(|| {
    env::var(ENV_SMTP_TEMPLATES).unwrap_or_else(|_| DEFAULT_TEMPLATES_PATH.to_string())
});

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("smtp transport is not valid")]
    NotATransport,
    #[error("{0}")]
    Parse(#[from] std::num::ParseIntError),
    #[error("{0}")]
    Transport(#[from] lettre::transport::smtp::Error),
    #[error("{0}")]
    Address(#[from] lettre::address::AddressError),
    #[error("{0}")]
    Lettre(#[from] lettre::error::Error),
}

/// A builder for the [Smtp] struct.
#[derive(Default)]
pub struct SmtpBuilder<'a> {
    pub issuer: &'a str,
    pub origin: &'a str,
    pub transport: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

impl<'a> SmtpBuilder<'a> {
    pub fn build(&self) -> Result<Smtp<'a>> {
        let transport_attrs: Vec<&str> = self.transport.split(':').collect();
        if transport_attrs.is_empty() || transport_attrs[0].is_empty() {
            return Err(Error::NotATransport);
        }

        let mut transport = SmtpTransport::relay(transport_attrs[0])
            .map_err(on_error!(Error, "creating a smtp transport"))?;

        if transport_attrs.len() > 1 && !transport_attrs[1].is_empty() {
            let port: u16 = transport_attrs[1].parse().map_err(on_error!(
                ParseIntError as Error,
                "parsing string into port number"
            ))?;

            transport = transport.port(port);
        }

        if !self.username.is_empty() && !self.password.is_empty() {
            let creds = Credentials::new(self.username.to_string(), self.password.to_string());
            transport = transport.credentials(creds);
        } else {
            warn!("tls is disabled for smtp");
            transport = transport.tls(Tls::None);
        }

        let mailbox: Mailbox = self.origin.parse().map_err(on_error!(
            AddressError as Error,
            "parsing origin into a mailbox"
        ))?;

        Ok(Smtp {
            issuer: self.issuer,
            origin: mailbox,
            transport: transport.build(),
        })
    }
}

/// Smtp represents an email sender.
pub struct Smtp<'a> {
    pub issuer: &'a str,
    pub origin: Mailbox,
    pub transport: SmtpTransport,
}

impl<'a> Smtp<'a> {
    #[instrument(skip(self))]
    pub fn send(&self, to: &Email, subject: &str, body: &str) -> Result<()> {
        let formated_subject = self
            .issuer
            .is_empty()
            .then_some(subject.to_string())
            .unwrap_or_else(|| format!("[{}] {subject}", self.issuer));

        let to = to.as_ref().parse().map_err(on_error!(
            AddressError as Error,
            "parsing email destination"
        ))?;

        let email = Message::builder()
            .from(self.origin.clone())
            .to(to)
            .subject(formated_subject)
            .singlepart(SinglePart::html(body.to_string()))
            .map_err(on_error!(Error, "building email message"))?;

        self.transport
            .send(&email)
            .map_err(on_error!(Error, "sending email"))?;

        Ok(())
    }
}
