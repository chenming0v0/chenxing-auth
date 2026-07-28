use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MIN_PASSWORD_LENGTH: usize = 10;
pub type UserId = i64;

#[derive(Debug, Deserialize)]
pub struct RegistrationInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginInput {
    #[serde(alias = "email")]
    pub identifier: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLogin {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoginError {
    #[error("username or email is invalid")]
    InvalidIdentifier,
    #[error("password is empty")]
    EmptyPassword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRegistration {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("username is invalid")]
    InvalidUsername,
    #[error("email is invalid")]
    InvalidEmail,
    #[error("password must be at least {MIN_PASSWORD_LENGTH} characters")]
    PasswordTooShort,
    #[error("display name is too long")]
    DisplayNameTooLong,
}

pub fn validate_registration(
    input: RegistrationInput,
) -> Result<ValidatedRegistration, RegistrationError> {
    let email = input.email.trim().to_ascii_lowercase();
    if !is_valid_email(&email) {
        return Err(RegistrationError::InvalidEmail);
    }
    if input.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(RegistrationError::PasswordTooShort);
    }

    let display_name = validate_display_name(input.display_name)?;
    let username = validate_username(&input.username).ok_or(RegistrationError::InvalidUsername)?;

    Ok(ValidatedRegistration {
        username,
        email,
        password: input.password,
        display_name,
    })
}

pub fn validate_display_name(
    display_name: Option<String>,
) -> Result<Option<String>, RegistrationError> {
    let display_name = display_name.and_then(|name| {
        let name = name.trim().to_owned();
        (!name.is_empty()).then_some(name)
    });
    if display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 128)
    {
        return Err(RegistrationError::DisplayNameTooLong);
    }
    Ok(display_name)
}

pub fn validate_login(input: LoginInput) -> Result<ValidatedLogin, LoginError> {
    let identifier = input.identifier.trim().to_ascii_lowercase();
    if !is_valid_email(&identifier) && validate_username(&identifier).is_none() {
        return Err(LoginError::InvalidIdentifier);
    }
    if input.password.is_empty() {
        return Err(LoginError::EmptyPassword);
    }

    Ok(ValidatedLogin {
        identifier,
        password: input.password,
    })
}

pub fn validate_username(username: &str) -> Option<String> {
    let username = username.trim().to_ascii_lowercase();
    let length = username.chars().count();
    if !(3..=64).contains(&length)
        || username.contains('@')
        || username.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(username)
}

fn is_valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !email.chars().any(char::is_whitespace)
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: time::OffsetDateTime,
}
