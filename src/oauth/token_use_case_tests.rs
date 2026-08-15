use super::token_final_fence::{consent_fence_holds, session_epoch_fence_holds};
use super::*;
use crate::clock::SharedClock;
use crate::consents::domain::ConsentState;
use crate::oauth::code::{AUTHORIZATION_CODE_TTL_SECONDS, AuthorizationCode};
use std::sync::{Arc, Barrier, Mutex};
use time::{Duration, OffsetDateTime};

const CLIENT_ID: &str = "cx_client";
const REDIRECT_URI: &str = "https://client.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// 授权码的签发时刻。固定值而不是 `now()`：TTL 边界要能被算出来，
/// 而不是"取决于用例什么时候跑"。
const ISSUED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

fn authorization_code() -> AuthorizationCode {
    AuthorizationCode::new_at(
        CLIENT_ID.to_owned(),
        REDIRECT_URI.to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        CHALLENGE.to_owned(),
        ISSUED_AT,
    )
}

/// 判定时刻由固定时钟提供，与生产路径取 `state.clock.now()` 的方式一致。
fn now_at(offset: Duration) -> OffsetDateTime {
    SharedClock::fixed(ISSUED_AT + offset).now()
}

#[test]
fn binding_and_pkce_validation_accepts_a_valid_code_without_consuming_it() {
    let code = authorization_code();

    assert!(
        validate_code_binding(
            CLIENT_ID,
            REDIRECT_URI,
            VERIFIER,
            &code,
            now_at(Duration::ZERO)
        )
        .is_ok()
    );
    assert!(code.redeemed_at.is_none());
}

#[test]
fn redirect_binding_is_rejected_as_invalid_grant() {
    let code = authorization_code();

    let error = validate_code_binding(
        CLIENT_ID,
        "https://attacker.example/callback",
        VERIFIER,
        &code,
        now_at(Duration::ZERO),
    )
    .expect_err("redirect URI mismatch must reject the code");

    assert_eq!(error, OAuthError::invalid_grant());
}

#[test]
fn expired_code_is_rejected_before_pkce_and_remains_unconsumed() {
    let code = authorization_code();

    // 不改 `expires_at`，改"现在"：把时钟推到 TTL 之后，与生产里授权码自然
    // 过期的路径完全一致。
    let error = validate_code_binding(
        CLIENT_ID,
        REDIRECT_URI,
        "invalid-verifier-that-would-fail-pkce-too",
        &code,
        now_at(Duration::seconds(AUTHORIZATION_CODE_TTL_SECONDS as i64)),
    )
    .expect_err("expired code must reject");

    assert_eq!(error, OAuthError::invalid_grant());
    assert!(code.redeemed_at.is_none());
}

#[test]
fn pkce_mismatch_is_rejected_without_consuming_the_code() {
    let code = authorization_code();

    let error = validate_code_binding(
        CLIENT_ID,
        REDIRECT_URI,
        "a".repeat(43).as_str(),
        &code,
        now_at(Duration::ZERO),
    )
    .expect_err("PKCE mismatch must reject");

    assert_eq!(error, OAuthError::invalid_grant());
    assert!(code.redeemed_at.is_none());
}

/// Issue #299：授权码的过期判定必须能被固定时钟推到边界两侧。
///
/// `expires_at` 是排他上界（`redeem_at` 用 `now >= expires_at` 拒绝），所以
/// 「差一秒」可兑换、「正好到点」不可兑换。以前这条判定读进程墙钟，
/// 只能验证"很久以前"和"现在"，无法验证边界本身落在哪一侧。
#[test]
fn authorization_code_redeemability_flips_exactly_at_expiry() {
    let code = authorization_code();
    let ttl = Duration::seconds(AUTHORIZATION_CODE_TTL_SECONDS as i64);

    assert!(
        validate_code_binding(
            CLIENT_ID,
            REDIRECT_URI,
            VERIFIER,
            &code,
            now_at(ttl - Duration::seconds(1))
        )
        .is_ok(),
        "到期前一秒必须仍可兑换"
    );
    assert_eq!(
        validate_code_binding(CLIENT_ID, REDIRECT_URI, VERIFIER, &code, now_at(ttl))
            .expect_err("到期时刻必须拒绝"),
        OAuthError::invalid_grant()
    );
}

#[test]
fn final_code_fences_reject_a_barriered_revoke_and_epoch_advance() {
    let state = Arc::new(Mutex::new((ConsentState::new(false, 1), Some(7_i64))));
    let gate_started = Arc::new(Barrier::new(2));
    let revoke_committed = Arc::new(Barrier::new(2));
    let exchange_state = state.clone();
    let exchange_gate_started = gate_started.clone();
    let exchange_revoke_committed = revoke_committed.clone();
    let exchange = std::thread::spawn(move || {
        let (consent, epoch) = *exchange_state.lock().expect("exchange state");
        let observed_consent_version = consent.version;
        let observed_epoch = epoch.expect("epoch");
        exchange_gate_started.wait();
        exchange_revoke_committed.wait();
        let (current_consent, current_epoch) = *exchange_state.lock().expect("final state");
        (
            consent_fence_holds(Some(current_consent), observed_consent_version),
            session_epoch_fence_holds(current_epoch, observed_epoch),
        )
    });

    gate_started.wait();
    {
        let mut state = state.lock().expect("revoke state");
        state.0 = ConsentState::new(true, 2);
        state.1 = Some(8);
    }
    revoke_committed.wait();

    let (consent_ok, epoch_ok) = exchange.join().expect("exchange join");
    assert!(
        !consent_ok,
        "the final consent fence must reject the revoke race"
    );
    assert!(
        !epoch_ok,
        "the final epoch fence must reject the epoch race"
    );
}
