use crate::users::email::EmailAddress;
use std::{fmt, future::Future, pin::Pin};

#[derive(Clone)]
pub struct EmailMessage {
    pub to: EmailAddress,
    pub subject: String,
    pub body: String,
}
impl fmt::Debug for EmailMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailMessage")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmailSendError {
    #[error("email delivery is not configured")]
    NotConfigured,
    #[error("email delivery configuration is invalid")]
    InvalidConfiguration,
    #[error("email delivery failed")]
    Delivery,
}

/// Application boundary for one SMTP delivery attempt.
///
/// `Ok(())` means the provider boundary accepted this attempt; it does not
/// make the surrounding outbox transaction durable or provide idempotency.
/// Callers that persist delivery state after `send` must therefore tolerate a
/// later retry and possible duplicate external delivery.
pub trait EmailSender: Send + Sync {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::email::EmailAddress;

    struct FakeSender;
    impl EmailSender for FakeSender {
        fn send<'a>(
            &'a self,
            _message: EmailMessage,
        ) -> Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn fake_sender_is_injectable_and_message_debug_is_redacted() {
        let sender = FakeSender;
        let message = EmailMessage {
            to: EmailAddress::parse("user@example.com").unwrap(),
            subject: "code".into(),
            body: "verification code 123456".into(),
        };
        let debug = format!("{message:?}");
        assert!(!debug.contains("123456"));
        sender.send(message).await.unwrap();
    }
}
