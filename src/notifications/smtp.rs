use crate::{
    notifications::email::{EmailMessage, EmailSendError, EmailSender},
    settings::SettingsService,
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use std::{future::Future, pin::Pin};

#[derive(Clone)]
pub struct SmtpEmailSender {
    settings: SettingsService,
}
impl SmtpEmailSender {
    pub fn new(settings: SettingsService) -> Self {
        Self { settings }
    }
    async fn send_message(&self, message: EmailMessage) -> Result<(), EmailSendError> {
        let config = self
            .settings
            .smtp_delivery_config()
            .await
            .map_err(|_| EmailSendError::NotConfigured)?;
        if config.host.is_empty() || config.from_address.is_empty() {
            return Err(EmailSendError::NotConfigured);
        }
        let from: Mailbox = config
            .from_address
            .parse()
            .map_err(|_| EmailSendError::InvalidConfiguration)?;
        let to: Mailbox = message
            .to
            .to_string()
            .parse()
            .map_err(|_| EmailSendError::InvalidConfiguration)?;
        let email = Message::builder()
            .from(from)
            .to(to)
            .subject(message.subject)
            .body(message.body)
            .map_err(|_| EmailSendError::InvalidConfiguration)?;
        if config.username.is_empty() != config.password.is_empty()
            || (config.force_auth_login && config.username.is_empty())
        {
            return Err(EmailSendError::InvalidConfiguration);
        }
        let mut client = if config.ssl_enabled {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        }
        .map_err(|_| EmailSendError::InvalidConfiguration)?
        .port(config.port);
        if !config.username.is_empty() {
            client = client.credentials(Credentials::new(config.username, config.password));
        }
        client
            .build()
            .send(email)
            .await
            .map(|_| ())
            .map_err(|_| EmailSendError::Delivery)
    }
}
impl EmailSender for SmtpEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>> {
        Box::pin(self.send_message(message))
    }
}
