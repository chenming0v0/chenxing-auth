use chenxing_auth::auth_factors::totp::{
    TotpEnrollment, verify_totp_code_at, verify_totp_code_at_timestep,
};
use std::time::Duration;

#[test]
fn enrollment_produces_google_authenticator_compatible_uri_and_code() {
    let enrollment = TotpEnrollment::new("user@example.com", "Chenxing Pass").expect("enrollment");
    assert!(enrollment.otpauth_url().starts_with("otpauth://totp/"));
    assert!(enrollment.otpauth_url().contains("issuer=Chenxing%20Pass"));
    assert_eq!(enrollment.secret_base32().len() % 8, 0);

    let now = 1_700_000_000_u64;
    let code = enrollment.code_at(now);
    assert!(verify_totp_code_at(enrollment.secret_bytes(), &code, now));
    assert!(!verify_totp_code_at(
        enrollment.secret_bytes(),
        "000000",
        now
    ));
}

#[test]
fn totp_allows_only_the_one_step_clock_skew() {
    let enrollment = TotpEnrollment::new("user@example.com", "Chenxing Pass").expect("enrollment");
    let now = 1_700_000_000_u64;
    let previous_code = enrollment.code_at(now - 30);
    assert!(verify_totp_code_at(
        enrollment.secret_bytes(),
        &previous_code,
        now
    ));
    assert!(!verify_totp_code_at(
        enrollment.secret_bytes(),
        &enrollment.code_at(now - 60 - Duration::from_secs(1).as_secs()),
        now
    ));
}

#[test]
fn totp_validation_returns_the_accepted_time_step() {
    let enrollment = TotpEnrollment::new("user@example.com", "Chenxing Pass").expect("enrollment");
    let now = 1_700_000_000_u64;
    let code = enrollment.code_at(now - 30);

    assert_eq!(
        verify_totp_code_at_timestep(enrollment.secret_bytes(), &code, now),
        Some((now - 30) / 30)
    );
    assert_eq!(
        verify_totp_code_at_timestep(enrollment.secret_bytes(), "000000", now),
        None
    );
}
