use axum::{
    extract::{ConnectInfo, Extension},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::proto::CreationChallengeResponse;

use crate::{auth_factors::service::AuthFactorServiceError, error, state::AppState};

pub use super::enrollment_handlers::{
    cancel_security_factor_enrollment, confirm_security_totp_enrollment, current_security_factors,
    finish_security_passkey_registration, start_security_passkey_registration,
    start_security_totp_enrollment,
};
pub use super::removal_handlers::{remove_security_passkey_factor, remove_security_totp_factor};

#[derive(Debug, Serialize)]
pub struct FactorSummaryResponse {
    pub(crate) totp_enabled: bool,
    pub(crate) passkey_count: i64,
    pub(crate) available_methods: Vec<crate::auth_factors::domain::FactorMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[derive(Debug, Serialize)]
pub struct TotpStartResponse<'a> {
    pub(crate) enrollment_id: &'a str,
    pub(crate) secret_base32: &'a str,
    pub(crate) otpauth_url: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfirmInput {
    pub(super) enrollment_id: String,
    pub(super) code: String,
}

impl fmt::Debug for TotpConfirmInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfirmInput")
            .field("enrollment_id", &self.enrollment_id)
            .field("code", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct PasskeyStartResponse {
    pub(crate) enrollment_id: String,
    pub(crate) options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyFinishInput {
    pub(super) enrollment_id: String,
    pub(super) credential: RegisterPublicKeyCredential,
}

impl fmt::Debug for PasskeyFinishInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyFinishInput")
            .field("enrollment_id", &self.enrollment_id)
            .field("credential", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorRemovalInput {
    pub(super) password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelEnrollmentInput {
    pub(super) enrollment_id: String,
    pub(super) method: crate::auth_factors::domain::FactorMethod,
}

impl fmt::Debug for FactorRemovalInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FactorRemovalInput")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct EnrollmentResponse {
    pub(crate) method: &'static str,
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct RemovalResponse {
    pub(crate) method: &'static str,
    pub(crate) removed: i64,
    pub(crate) credentials_revoked: bool,
}

pub(crate) fn trusted_source_ip(
    state: &AppState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> Option<String> {
    crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        headers,
        &state.config.trusted_proxies,
    )
}

pub(crate) fn factor_internal(error_value: AuthFactorServiceError, operation: &str) -> Response {
    tracing::error!(error = %error_value, operation, "authentication factor operation failed");
    error::internal()
}
