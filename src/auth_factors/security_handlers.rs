use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr};
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::proto::CreationChallengeResponse;

use crate::{
    api::extract::{ApiJson, RequestIssuer, SessionRead, SessionWrite},
    audit::AuditEvent,
    auth_factors::service::{
        AuthFactorServiceError, EnrollmentFinish, EnrollmentStart, SelfServiceRemovalOutcome,
    },
    error,
    sessions::cookies,
    state::AppState,
    users::service::UserServiceError,
};

#[derive(Debug, Serialize)]
pub struct FactorSummaryResponse {
    totp_enabled: bool,
    passkey_count: i64,
    available_methods: Vec<crate::auth_factors::domain::FactorMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

#[derive(Debug, Serialize)]
pub struct TotpStartResponse<'a> {
    enrollment_id: &'a str,
    secret_base32: &'a str,
    otpauth_url: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfirmInput {
    enrollment_id: String,
    code: String,
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
    enrollment_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyFinishInput {
    enrollment_id: String,
    credential: RegisterPublicKeyCredential,
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
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelEnrollmentInput {
    enrollment_id: String,
    method: crate::auth_factors::domain::FactorMethod,
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
    method: &'static str,
    enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct RemovalResponse {
    method: &'static str,
    removed: i64,
    credentials_revoked: bool,
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
