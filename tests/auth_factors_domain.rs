use chenxing_auth::auth_factors::{
    crypto::{decrypt_totp_secret, encrypt_totp_secret},
    domain::{FactorMethod, LoginTicket, validate_totp_code},
};
use uuid::Uuid;

#[test]
fn totp_code_must_be_exactly_six_ascii_digits() {
    assert!(validate_totp_code("012345").is_ok());
    assert!(validate_totp_code("12345").is_err());
    assert!(validate_totp_code("1234567").is_err());
    assert!(validate_totp_code("１２３４５６").is_err());
    assert!(validate_totp_code("12a456").is_err());
}

#[test]
fn totp_secret_encryption_round_trips_with_application_key() {
    let key = [7_u8; 32];
    let secret = b"JBSWY3DPEHPK3PXP";
    let encrypted = encrypt_totp_secret(&key, secret).expect("encrypt secret");
    assert_ne!(encrypted, secret);
    assert_eq!(
        decrypt_totp_secret(&key, &encrypted).expect("decrypt secret"),
        secret
    );
    assert!(decrypt_totp_secret(&[8_u8; 32], &encrypted).is_err());
}

#[test]
fn login_ticket_exposes_only_configured_factor_methods() {
    let user_id = Uuid::new_v4();
    let ticket = LoginTicket::new(user_id, vec![FactorMethod::Totp, FactorMethod::Passkey]);

    assert_eq!(ticket.user_id, user_id);
    assert_eq!(
        ticket.methods(),
        &[FactorMethod::Totp, FactorMethod::Passkey]
    );
    assert!(ticket.is_active_at(ticket.expires_at - time::Duration::seconds(1)));
    assert!(!ticket.is_active_at(ticket.expires_at));
}
