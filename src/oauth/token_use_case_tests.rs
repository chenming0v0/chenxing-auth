use super::*;
use crate::clock::SharedClock;
use crate::oauth::code::{AUTHORIZATION_CODE_TTL_SECONDS, AuthorizationCode};
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
