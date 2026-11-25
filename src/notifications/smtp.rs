use crate::{
    notifications::email::{EmailMessage, EmailSendError, EmailSender},
    settings::{SettingsService, SmtpDeliveryConfig},
};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::Mailbox,
    transport::smtp::{
        AsyncSmtpTransportBuilder,
        authentication::{Credentials, Mechanism},
    },
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
        client_builder(config)?
            .build::<Tokio1Executor>()
            .send(email)
            .await
            .map(|_| ())
            .map_err(|_| EmailSendError::Delivery)
    }
}

fn client_builder(config: SmtpDeliveryConfig) -> Result<AsyncSmtpTransportBuilder, EmailSendError> {
    config
        .validate_authentication()
        .map_err(|_| EmailSendError::InvalidConfiguration)?;
    // 587 是标准提交端口，使用强制 STARTTLS；其余端口保留既有隐式 TLS 选择。
    // 两种构造器都校验证书和服务名，STARTTLS 不允许降级为明文投递。
    let mut client = if config.ssl_enabled && config.port != 587 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
    }
    .map_err(|_| EmailSendError::InvalidConfiguration)?
    .port(config.port);
    if config.force_auth_login {
        client = client.authentication(vec![Mechanism::Login]);
    }
    if !config.username.is_empty() {
        client = client.credentials(Credentials::new(config.username, config.password));
    }
    Ok(client)
}

impl EmailSender for SmtpEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>> {
        Box::pin(self.send_message(message))
    }
}

#[cfg(test)]
#[path = "smtp_tests.rs"]
mod tests;
