pub mod email;
pub mod smtp;

pub use email::{EmailMessage, EmailSendError, EmailSender};
pub use smtp::SmtpEmailSender;
