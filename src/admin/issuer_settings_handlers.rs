use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::domain::AdminPermission;
use crate::{
    api::extract::{AdminRead, AdminWrite},
    audit::AuditEvent,
    error,
    settings::issuer::{self, IssuerRecord},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct UpdateIssuerSetting {
    pub value: String,
    pub expected_generation: i64,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
pub struct IssuerRecordResponse {
    pub value: String,
    pub generation: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: time::OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct IssuerSettingResponse {
    pub persisted: Option<IssuerRecordResponse>,
    pub loaded: Option<IssuerRecordResponse>,
    pub phase: crate::settings::SystemPhase,
}

impl From<&IssuerRecord> for IssuerRecordResponse {
    fn from(record: &IssuerRecord) -> Self {
        Self {
            value: record.value.clone(),
            generation: record.generation,
            updated_at: record.updated_at,
        }
    }
}

fn issuer_setting_response(
    state: &AppState,
    persisted: Option<&IssuerRecord>,
) -> IssuerSettingResponse {
    let runtime = state.issuer.state();
    let loaded = runtime.loaded().map(|snapshot| IssuerRecordResponse {
        value: snapshot.issuer().as_str().to_owned(),
        generation: snapshot.generation(),
        updated_at: snapshot.updated_at(),
    });
    IssuerSettingResponse {
        persisted: persisted.map(IssuerRecordResponse::from),
        loaded,
        phase: runtime.phase(),
    }
}

pub async fn get_issuer_setting(State(state): State<AppState>, admin: AdminRead) -> Response {
    if let Err(response) = admin.authorize(&state, AdminPermission::ManageIssuer).await {
        return response;
    }
    match issuer::load_raw(&state.database).await {
        Ok(Some(raw)) => {
            let persisted = raw.value.as_deref().and_then(|value| {
                crate::config::IssuerUrl::parse(value)
                    .ok()
                    .map(|issuer| IssuerRecord {
                        value: issuer.as_str().to_owned(),
                        generation: raw.generation,
                        updated_at: raw.updated_at,
                    })
            });
            (
                StatusCode::OK,
                Json(issuer_setting_response(&state, persisted.as_ref())),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::OK, Json(issuer_setting_response(&state, None))).into_response(),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load issuer setting");
            error::internal()
        }
    }
}

pub async fn update_issuer_setting(
    State(state): State<AppState>,
    admin: AdminWrite,
    headers: HeaderMap,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(input): Json<UpdateIssuerSetting>,
) -> Response {
    let actor = match admin.authorize(&state, AdminPermission::ManageIssuer).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if input.expected_generation < 0 {
        return error::bad_request(
            "invalid_issuer_generation",
            "expected_generation is invalid",
        );
    }
    let value = match crate::config::IssuerUrl::parse(&input.value) {
        Ok(value) => value,
        Err(_) => {
            return error::bad_request(
                "invalid_issuer",
                "issuer must be an absolute http(s) root URL",
            );
        }
    };
    if let Err(error_value) = state.issuer.validate_value(&value) {
        tracing::info!(error = %error_value, "issuer update rejected by runtime policy");
        return error::bad_request(
            "invalid_issuer",
            "issuer configuration is incompatible with runtime security policy",
        );
    }
    let current = match issuer::load_raw(&state.database).await {
        Ok(current) => current,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to load issuer before update");
            return error::internal();
        }
    };
    let current_value = current.as_ref().and_then(|record| record.value.as_deref());
    if current_value.is_some_and(|current| current != value.as_str()) && !input.confirm {
        return error::conflict(
            "issuer_confirmation_required",
            "changing the issuer requires explicit confirmation",
        );
    }
    if let Some(snapshot) = state.issuer.current() {
        let defaults = match state.issuer.webauthn_defaults_for(&value) {
            Ok(defaults) => defaults,
            Err(error_value) => {
                tracing::info!(error = %error_value, "issuer update rejected by WebAuthn policy");
                return error::conflict(
                    "issuer_passkey_migration_required",
                    "issuer change is incompatible with the current WebAuthn configuration",
                );
            }
        };
        if defaults.0 != snapshot.webauthn_rp_id() || defaults.1 != snapshot.webauthn_origin() {
            match state.factors.has_passkeys().await {
                Ok(true) => {
                    return error::conflict(
                        "issuer_passkey_migration_required",
                        "configure a stable WebAuthn RP ID and origin before changing issuer",
                    );
                }
                Ok(false) => {}
                Err(error_value) => {
                    tracing::error!(error = %error_value, "failed to check passkey compatibility");
                    return error::service_unavailable(
                        "issuer_passkey_check_unavailable",
                        "could not verify WebAuthn compatibility",
                    );
                }
            }
        }
    }
    let mut transaction = match state.database.begin().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to begin issuer update transaction");
            return error::internal();
        }
    };
    let write =
        match issuer::set_in_transaction(&mut transaction, &value, input.expected_generation).await
        {
            Ok(Some(write)) => write,
            Ok(None) => {
                let _ = transaction.rollback().await;
                return error::conflict(
                    "issuer_generation_conflict",
                    "issuer changed; reload the setting and retry",
                );
            }
            Err(error_value) => {
                tracing::error!(error = %error_value, "failed to persist issuer setting");
                let _ = transaction.rollback().await;
                return error::internal();
            }
        };
    if !write.changed {
        if let Err(error_value) = transaction.commit().await {
            tracing::error!(error = %error_value, "failed to commit idempotent issuer update");
            return error::internal();
        }
        let _ = state.issuer.apply(&write.record);
        return (
            StatusCode::OK,
            Json(issuer_setting_response(&state, Some(&write.record))),
        )
            .into_response();
    }
    let source_ip = crate::api::source_ip(
        connect_info.map(|Extension(ConnectInfo(peer))| peer),
        &headers,
        &state.config.trusted_proxies,
    );
    let user_agent = crate::api::user_agent(&headers);
    let (actor_type, actor_id) = actor.audit_fields();
    let event = AuditEvent::new(
        actor_type.to_owned(),
        actor_id,
        if write.previous_value.is_some() {
            crate::audit::AuditAction::IssuerUpdate
        } else {
            crate::audit::AuditAction::IssuerConfigure
        },
        "setting".to_owned(),
        Some("app_issuer".to_owned()),
        crate::audit::with_request_context(
            serde_json::json!({
                "previous_value": write.previous_value,
                "value": write.record.value,
                "generation": write.record.generation,
            }),
            source_ip.as_deref(),
            user_agent.as_deref(),
        ),
    );
    if let Err(error_value) = state
        .audit
        .record_in_transaction(&mut transaction, event)
        .await
    {
        tracing::error!(error = %error_value, "failed to audit issuer update");
        let _ = transaction.rollback().await;
        return error::internal();
    }
    if let Err(error_value) = transaction.commit().await {
        tracing::error!(error = %error_value, "failed to commit issuer update");
        return error::internal();
    }
    if let Err(error_value) = state.issuer.apply(&write.record) {
        tracing::error!(error = %error_value, generation = write.record.generation, "issuer persisted but could not be loaded");
        return error::service_unavailable(
            "issuer_runtime_invalid",
            "the issuer was saved but could not be loaded",
        );
    }
    (
        StatusCode::OK,
        Json(issuer_setting_response(&state, Some(&write.record))),
    )
        .into_response()
}
