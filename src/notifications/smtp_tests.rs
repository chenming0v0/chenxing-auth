use super::*;
use crate::settings::SmtpSetting;

fn config(port: u16, ssl_enabled: bool) -> SmtpDeliveryConfig {
    SmtpDeliveryConfig {
        host: "smtp.example.com".to_owned(),
        port,
        username: "sender@example.com".to_owned(),
        from_address: "sender@example.com".to_owned(),
        ssl_enabled,
        force_auth_login: false,
        password: "fixture-password".to_owned(),
    }
}

#[test]
fn smtp_default_and_explicit_submission_port_require_starttls() {
    let default = SmtpSetting::default();
    assert_eq!(default.port, 587);
    for ssl_enabled in [default.ssl_enabled, false] {
        let client = client_builder(config(default.port, ssl_enabled)).expect("SMTP builder");
        assert!(format!("{client:?}").contains("tls: Required"));
    }
}

#[test]
fn smtp_keeps_implicit_tls_and_explicit_custom_port_modes() {
    for port in [465, 2465] {
        let client = client_builder(config(port, true)).expect("implicit TLS builder");
        assert!(format!("{client:?}").contains("tls: Wrapper"));
        assert!(format!("{client:?}").contains(&format!("port: {port}")));
    }
    for port in [465, 2525] {
        let client = client_builder(config(port, false)).expect("STARTTLS builder");
        assert!(format!("{client:?}").contains("tls: Required"));
        assert!(format!("{client:?}").contains(&format!("port: {port}")));
    }
}

#[test]
fn smtp_force_login_limits_mechanisms_and_false_keeps_library_defaults() {
    let mut forced = config(587, true);
    forced.force_auth_login = true;
    let client = client_builder(forced).expect("forced LOGIN builder");
    assert!(format!("{client:?}").contains("authentication: [Login]"));

    let client = client_builder(config(587, true)).expect("default authentication builder");
    let defaults = lettre::transport::smtp::authentication::DEFAULT_MECHANISMS;
    assert!(format!("{client:?}").contains(&format!("authentication: {defaults:?}")));
}

#[test]
fn smtp_no_auth_relay_omits_credentials_and_rejects_partial_authentication() {
    let mut relay = config(587, true);
    relay.username.clear();
    relay.password.clear();
    let client = client_builder(relay.clone()).expect("no-auth relay builder");
    assert!(format!("{client:?}").contains("credentials: None"));

    relay.force_auth_login = true;
    assert!(client_builder(relay).is_err());
    let mut partial = config(587, true);
    partial.username.clear();
    assert!(client_builder(partial).is_err());
    let mut partial = config(587, true);
    partial.password.clear();
    assert!(client_builder(partial).is_err());
}
