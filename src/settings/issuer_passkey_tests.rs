use time::OffsetDateTime;

use super::{
    issuer::{IssuerRecord, RawIssuerRecord},
    issuer_passkey::{
        CurrentWebAuthnIdentity, current_webauthn_baseline, webauthn_identity_matches,
    },
    issuer_runtime::IssuerRuntime,
};
use crate::config::Config;

fn derived_config() -> Config {
    let mut config = Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned(),
        "redis://127.0.0.1:6379".to_owned(),
        3600,
    )
    .expect("config");
    config.webauthn_rp_id_explicit = false;
    config.webauthn_origin_explicit = false;
    config
}

fn explicit_config() -> Config {
    Config::from_values(
        "127.0.0.1".to_owned(),
        3000,
        "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned(),
        "redis://127.0.0.1:6379".to_owned(),
        3600,
    )
    .expect("config")
}

fn raw(value: Option<&str>, generation: i64) -> RawIssuerRecord {
    RawIssuerRecord {
        value: value.map(str::to_owned),
        generation,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn record(value: &str, generation: i64) -> IssuerRecord {
    IssuerRecord {
        value: value.to_owned(),
        generation,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn awaiting() -> IssuerRuntime {
    IssuerRuntime::new(&derived_config(), None).expect("awaiting runtime")
}

fn ready(value: &str, generation: i64) -> IssuerRuntime {
    IssuerRuntime::new(&derived_config(), Some(&record(value, generation))).expect("ready runtime")
}

fn identity_change_requires_passkey_check(
    runtime: &IssuerRuntime,
    persisted: Option<&RawIssuerRecord>,
    new_issuer: &str,
) -> bool {
    let config = derived_config();
    let new_defaults = runtime
        .webauthn_defaults_for(&crate::config::IssuerUrl::parse(new_issuer).expect("issuer"))
        .expect("new defaults");
    let baseline = current_webauthn_baseline(
        runtime,
        persisted,
        &config.webauthn_rp_id,
        &config.webauthn_origin,
    );
    !webauthn_identity_matches(baseline.as_ref(), &new_defaults.0, &new_defaults.1)
}

#[test]
fn awaiting_runtime_still_uses_persisted_issuer() {
    let runtime = awaiting();
    assert!(runtime.current().is_none());
    let persisted = raw(Some("https://auth.example.com"), 1);
    assert_eq!(
        CurrentWebAuthnIdentity::from_runtime_and_persisted(&runtime, Some(&persisted)),
        CurrentWebAuthnIdentity::Known {
            rp_id: "auth.example.com".to_owned(),
            origin: "https://auth.example.com".to_owned(),
        }
    );
    assert!(identity_change_requires_passkey_check(
        &runtime,
        Some(&persisted),
        "https://other.example.com",
    ));
}

#[test]
fn first_time_issuer_without_persisted_row_uses_bootstrap_defaults() {
    let runtime = awaiting();
    let config = derived_config();
    assert_eq!(
        CurrentWebAuthnIdentity::from_runtime_and_persisted(&runtime, None),
        CurrentWebAuthnIdentity::Absent
    );
    let baseline = current_webauthn_baseline(
        &runtime,
        None,
        &config.webauthn_rp_id,
        &config.webauthn_origin,
    );
    assert_eq!(
        baseline
            .as_ref()
            .map(|(rp_id, origin)| (rp_id.as_str(), origin.as_str())),
        Some(("localhost", "http://localhost:3000"))
    );
    assert!(identity_change_requires_passkey_check(
        &runtime,
        None,
        "https://auth.example.com",
    ));
}

#[test]
fn pending_or_invalid_persisted_row_cannot_prove_compatibility() {
    let runtime = awaiting();
    for persisted in [
        raw(None, 1),
        raw(Some(""), 1),
        raw(Some("   "), 1),
        raw(Some("not-a-url"), 1),
    ] {
        assert_eq!(
            CurrentWebAuthnIdentity::from_runtime_and_persisted(&runtime, Some(&persisted)),
            CurrentWebAuthnIdentity::UnknownPersisted,
            "record={persisted:?}"
        );
        let baseline = current_webauthn_baseline(
            &runtime,
            Some(&persisted),
            "localhost",
            "http://localhost:3000",
        );
        assert!(baseline.is_none(), "record={persisted:?}");
        assert!(!webauthn_identity_matches(
            baseline.as_ref(),
            "auth.example.com",
            "https://auth.example.com",
        ));
    }
}

#[test]
fn persisted_issuer_wins_over_stale_runtime_snapshot() {
    let runtime = ready("https://old.example.com", 1);
    let persisted = raw(Some("https://auth.example.com"), 2);
    assert_eq!(
        CurrentWebAuthnIdentity::from_runtime_and_persisted(&runtime, Some(&persisted)),
        CurrentWebAuthnIdentity::Known {
            rp_id: "auth.example.com".to_owned(),
            origin: "https://auth.example.com".to_owned(),
        }
    );
    assert!(!identity_change_requires_passkey_check(
        &runtime,
        Some(&persisted),
        "https://auth.example.com",
    ));
}

#[test]
fn explicit_webauthn_overrides_keep_issuer_changes_compatible() {
    let runtime = IssuerRuntime::new(&explicit_config(), None).expect("awaiting");
    let persisted = raw(Some("https://auth.example.com"), 1);
    let new_defaults = runtime
        .webauthn_defaults_for(
            &crate::config::IssuerUrl::parse("https://other.example.com").expect("issuer"),
        )
        .expect("defaults");
    let baseline = current_webauthn_baseline(
        &runtime,
        Some(&persisted),
        &explicit_config().webauthn_rp_id,
        &explicit_config().webauthn_origin,
    );
    assert!(webauthn_identity_matches(
        baseline.as_ref(),
        &new_defaults.0,
        &new_defaults.1,
    ));
}

#[test]
fn matching_identity_does_not_require_a_passkey_check() {
    let runtime = awaiting();
    let persisted = raw(Some("https://auth.example.com"), 1);
    assert!(!identity_change_requires_passkey_check(
        &runtime,
        Some(&persisted),
        "https://auth.example.com",
    ));
}

#[test]
fn unknown_persisted_identity_is_incompatible_until_passkeys_are_absent() {
    assert!(!webauthn_identity_matches(
        None,
        "auth.example.com",
        "https://auth.example.com",
    ));
}
