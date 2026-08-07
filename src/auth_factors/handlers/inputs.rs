use serde::{Deserialize, Serialize};
use std::fmt;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

#[derive(Deserialize)]
pub struct TotpSetupInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
}

impl fmt::Debug for TotpSetupInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSetupInput")
            .field("login_ticket", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
pub(super) struct TotpSetupResponse<'a> {
    pub(super) secret_base32: &'a str,
    pub(super) otpauth_url: &'a str,
}

impl fmt::Debug for TotpSetupResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSetupResponse")
            .field("secret_base32", &"<redacted>")
            .field("otpauth_url", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct TotpConfirmInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
    pub code: String,
}

impl fmt::Debug for TotpConfirmInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfirmInput")
            .field("login_ticket", &"<redacted>")
            .field("code", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct TotpLoginInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
    pub code: String,
}

impl fmt::Debug for TotpLoginInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpLoginInput")
            .field("login_ticket", &"<redacted>")
            .field("code", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct PasskeyTicketInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
}

impl fmt::Debug for PasskeyTicketInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyTicketInput")
            .field("login_ticket", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct PasskeyRegistrationInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
    pub credential: RegisterPublicKeyCredential,
}

impl fmt::Debug for PasskeyRegistrationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyRegistrationInput")
            .field("login_ticket", &"<redacted>")
            .field("credential", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
pub struct PasskeyAuthenticationInput {
    #[serde(default)]
    pub login_ticket: Option<String>,
    pub credential: PublicKeyCredential,
}

impl fmt::Debug for PasskeyAuthenticationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyAuthenticationInput")
            .field("login_ticket", &"<redacted>")
            .field("credential", &"<redacted>")
            .finish()
    }
}
