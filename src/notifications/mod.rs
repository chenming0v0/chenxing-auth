pub(crate) mod crypto;
mod outbox;

pub mod email;
pub mod smtp;

pub use email::{EmailMessage, EmailSendError, EmailSender};
pub use outbox::{EmailOutbox, EmailOutboxError};
pub use smtp::SmtpEmailSender;
