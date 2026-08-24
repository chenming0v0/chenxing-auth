use axum::response::Response;

use crate::{
    error,
    settings::{
        issuer,
        issuer_passkey::{current_webauthn_baseline, webauthn_identity_matches},
    },
    state::AppState,
};

/// Reject an issuer write that would rebind existing Passkeys to a new RP ID/origin.
///
/// The check uses the persisted issuer inside the update transaction. Runtime
/// Awaiting/Pending/Invalid have no snapshot and must not skip this guard.
pub(crate) async fn reject_if_issuer_breaks_existing_passkeys(
    state: &AppState,
    transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
    new_issuer: &crate::config::IssuerUrl,
) -> Result<(), Response> {
    let new_defaults = match state.issuer.webauthn_defaults_for(new_issuer) {
        Ok(defaults) => defaults,
        Err(error_value) => {
            tracing::info!(error = %error_value, "issuer update rejected by WebAuthn policy");
            return Err(error::conflict(
                "issuer_passkey_migration_required",
                "issuer change is incompatible with the current WebAuthn configuration",
            ));
        }
    };
    let persisted = match issuer::load_raw(&mut **transaction).await {
        Ok(persisted) => persisted,
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                "failed to load issuer for passkey compatibility"
            );
            return Err(error::internal());
        }
    };
    let baseline = current_webauthn_baseline(
        &state.issuer,
        persisted.as_ref(),
        &state.config.webauthn_rp_id,
        &state.config.webauthn_origin,
    );
    if webauthn_identity_matches(baseline.as_ref(), &new_defaults.0, &new_defaults.1) {
        return Ok(());
    }
    match state.factors.has_passkeys_in_transaction(transaction).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(error::conflict(
            "issuer_passkey_migration_required",
            "configure a stable WebAuthn RP ID and origin before changing issuer",
        )),
        Err(error_value) => {
            tracing::error!(error = %error_value, "failed to check passkey compatibility");
            Err(error::service_unavailable(
                "issuer_passkey_check_unavailable",
                "could not verify WebAuthn compatibility",
            ))
        }
    }
}
