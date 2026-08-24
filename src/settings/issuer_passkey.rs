//! WebAuthn identity for issuer updates, independent of runtime snapshot phase.
//!
//! Existing Passkeys are bound to RP ID/origin. An issuer write may change those
//! derived values. The durable current issuer lives in PostgreSQL; Awaiting,
//! Pending, and Invalid runtimes have no snapshot and must still consult that row.

use super::{
    issuer::RawIssuerRecord,
    issuer_runtime::{IssuerRuntime, IssuerSnapshot},
};
use crate::config::IssuerUrl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CurrentWebAuthnIdentity {
    Known {
        rp_id: String,
        origin: String,
    },
    /// A persisted issuer row exists but cannot yield RP ID/origin.
    UnknownPersisted,
    Absent,
}

impl CurrentWebAuthnIdentity {
    /// Prefer the persisted issuer. The in-memory snapshot is only a fallback
    /// when the durable row is missing or unusable.
    pub(crate) fn from_runtime_and_persisted(
        runtime: &IssuerRuntime,
        persisted: Option<&RawIssuerRecord>,
    ) -> Self {
        if let Some(record) = persisted {
            if let Some((rp_id, origin)) = identity_from_record(runtime, record) {
                return Self::Known { rp_id, origin };
            }
            if let Some(snapshot) = runtime.current() {
                return Self::from_snapshot(&snapshot);
            }
            return Self::UnknownPersisted;
        }
        if let Some(snapshot) = runtime.current() {
            return Self::from_snapshot(&snapshot);
        }
        Self::Absent
    }

    fn from_snapshot(snapshot: &IssuerSnapshot) -> Self {
        Self::Known {
            rp_id: snapshot.webauthn_rp_id().to_owned(),
            origin: snapshot.webauthn_origin().to_owned(),
        }
    }

    /// Identity existing Passkeys are bound to. `None` means compatibility
    /// cannot be proved (persisted but unusable). First-time absence falls back
    /// to bootstrap WebAuthn defaults from config.
    pub(crate) fn baseline(
        &self,
        bootstrap_rp_id: &str,
        bootstrap_origin: &str,
    ) -> Option<(String, String)> {
        match self {
            Self::Known { rp_id, origin } => Some((rp_id.clone(), origin.clone())),
            Self::Absent => Some((bootstrap_rp_id.to_owned(), bootstrap_origin.to_owned())),
            Self::UnknownPersisted => None,
        }
    }
}

fn identity_from_record(
    runtime: &IssuerRuntime,
    record: &RawIssuerRecord,
) -> Option<(String, String)> {
    let value = record
        .value
        .as_deref()
        .filter(|value| !value.trim().is_empty())?;
    let issuer = IssuerUrl::parse(value).ok()?;
    runtime.webauthn_defaults_for(&issuer).ok()
}

pub(crate) fn current_webauthn_baseline(
    runtime: &IssuerRuntime,
    persisted: Option<&RawIssuerRecord>,
    bootstrap_rp_id: &str,
    bootstrap_origin: &str,
) -> Option<(String, String)> {
    CurrentWebAuthnIdentity::from_runtime_and_persisted(runtime, persisted)
        .baseline(bootstrap_rp_id, bootstrap_origin)
}

pub(crate) fn webauthn_identity_matches(
    baseline: Option<&(String, String)>,
    new_rp_id: &str,
    new_origin: &str,
) -> bool {
    matches!(
        baseline,
        Some((rp_id, origin)) if rp_id == new_rp_id && origin == new_origin
    )
}
