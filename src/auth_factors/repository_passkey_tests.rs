use super::authentication::{PasskeyMergeOutcome, apply_authentication_result};
use super::*;
use base64::Engine;
use webauthn_rs::prelude::AuthenticationResult;

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn test_passkey(credential_id: &[u8], counter: u32, backup_eligible: bool) -> Passkey {
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": encode(credential_id),
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": encode(&[4; 32]),
                        "y": encode(&[5; 32])
                    }
                }
            },
            "counter": counter,
            "transports": null,
            "user_verified": false,
            "backup_eligible": backup_eligible,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }
    }))
    .expect("test passkey")
}

fn authentication_result(
    credential_id: &[u8],
    counter: u32,
    backup_eligible: bool,
    backup_state: bool,
) -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
        "cred_id": encode(credential_id),
        "needs_update": true,
        "user_verified": true,
        "backup_state": backup_state,
        "backup_eligible": backup_eligible,
        "counter": counter,
        "extensions": {}
    }))
    .expect("authentication result")
}

fn counter_of(passkey: &Passkey) -> u32 {
    serde_json::to_value(passkey).expect("passkey JSON")["cred"]["counter"]
        .as_u64()
        .expect("counter") as u32
}

fn backup_eligible_of(passkey: &Passkey) -> bool {
    serde_json::to_value(passkey).expect("passkey JSON")["cred"]["backup_eligible"]
        .as_bool()
        .expect("backup_eligible")
}

#[test]
fn absent_issuer_row_matches_only_the_initial_runtime_generation() {
    let initial = super::super::INITIAL_ISSUER_GENERATION;
    assert!(issuer_generation_matches(None, initial));
    assert!(!issuer_generation_matches(None, initial + 1));
}

#[test]
fn merge_keeps_newer_counter_when_stale_result_arrives_later() {
    let credential_id = b"cred-1";
    let mut stored = test_passkey(credential_id, 2, false);
    let stale = authentication_result(credential_id, 1, false, false);
    assert_eq!(
        apply_authentication_result(&mut stored, &stale),
        PasskeyMergeOutcome::Unchanged
    );
    assert_eq!(counter_of(&stored), 2);
}

#[test]
fn merge_applies_newer_counter_onto_older_stored_state() {
    let credential_id = b"cred-1";
    let mut stored = test_passkey(credential_id, 1, false);
    let newer = authentication_result(credential_id, 2, false, false);
    assert_eq!(
        apply_authentication_result(&mut stored, &newer),
        PasskeyMergeOutcome::Changed
    );
    assert_eq!(counter_of(&stored), 2);
}

#[test]
fn merge_can_raise_backup_eligible_without_rewinding_counter() {
    let credential_id = b"cred-1";
    let mut stored = test_passkey(credential_id, 4, false);
    let stale_with_upgrade = authentication_result(credential_id, 3, true, true);
    assert_eq!(
        apply_authentication_result(&mut stored, &stale_with_upgrade),
        PasskeyMergeOutcome::Changed
    );
    assert_eq!(counter_of(&stored), 4);
    assert!(backup_eligible_of(&stored));
}

#[test]
fn merge_rejects_result_for_a_different_credential() {
    let mut stored = test_passkey(b"cred-1", 1, false);
    let other = authentication_result(b"cred-2", 2, false, false);
    assert_eq!(
        apply_authentication_result(&mut stored, &other),
        PasskeyMergeOutcome::Mismatch
    );
    assert_eq!(counter_of(&stored), 1);
}
