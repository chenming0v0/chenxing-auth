use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Secret, TOTP};

use super::domain::validate_totp_code;

const TOTP_DIGITS: usize = 6;
pub(crate) const TOTP_SKEW: u8 = 1;
pub(crate) const TOTP_STEP_SECONDS: u64 = 30;

#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    secret: Vec<u8>,
    secret_base32: String,
    otpauth_url: String,
}

impl TotpEnrollment {
    pub fn new(account_name: &str, issuer: &str) -> Result<Self, totp_rs::TotpUrlError> {
        let secret = Secret::generate_secret().to_bytes().map_err(|_| {
            totp_rs::TotpUrlError::Secret("could not generate TOTP secret".to_owned())
        })?;
        let totp = build_totp(secret.clone(), account_name, issuer)?;
        Ok(Self {
            secret,
            secret_base32: totp.get_secret_base32(),
            otpauth_url: totp.get_url(),
        })
    }

    pub fn from_secret(secret: Vec<u8>, account_name: &str, issuer: &str) -> Option<Self> {
        let totp = build_totp(secret.clone(), account_name, issuer).ok()?;
        Some(Self {
            secret,
            secret_base32: totp.get_secret_base32(),
            otpauth_url: totp.get_url(),
        })
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    pub fn secret_base32(&self) -> &str {
        &self.secret_base32
    }

    pub fn otpauth_url(&self) -> &str {
        &self.otpauth_url
    }

    pub fn code_at(&self, timestamp: u64) -> String {
        build_totp(self.secret.clone(), "", "")
            .expect("enrollment secret is valid")
            .generate(timestamp)
    }
}

pub fn verify_totp_code_at(secret: &[u8], code: &str, timestamp: u64) -> bool {
    verify_totp_code_at_timestep(secret, code, timestamp).is_some()
}

pub fn verify_totp_code_at_timestep(
    secret: &[u8],
    code: &str,
    timestamp: u64,
) -> Option<u64> {
    if validate_totp_code(code).is_err() {
        return None;
    }
    let totp = build_totp(secret.to_vec(), "", "").ok()?;
    let current_step = timestamp / TOTP_STEP_SECONDS;
    for offset in -(TOTP_SKEW as i64)..=(TOTP_SKEW as i64) {
        let step = current_step as i64 + offset;
        if step >= 0 && totp.generate((step as u64) * TOTP_STEP_SECONDS) == code {
            return Some(step as u64);
        }
    }
    None
}

pub fn verify_totp_code_current(secret: &[u8], code: &str) -> bool {
    verify_totp_code_current_timestep(secret, code).is_some()
}

pub fn verify_totp_code_current_timestep(secret: &[u8], code: &str) -> Option<u64> {
    let Ok(timestamp) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return None;
    };
    verify_totp_code_at_timestep(secret, code, timestamp.as_secs())
}

fn build_totp(
    secret: Vec<u8>,
    account_name: &str,
    issuer: &str,
) -> Result<TOTP, totp_rs::TotpUrlError> {
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECONDS,
        secret,
        Some(issuer.to_owned()),
        account_name.to_owned(),
    )
}
