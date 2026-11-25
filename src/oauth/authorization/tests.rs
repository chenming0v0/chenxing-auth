use super::{
    AuthorizationRequestError, PromptOptions, authentication_is_fresh,
    reauthentication_is_satisfied,
};
use time::{Duration, OffsetDateTime};

#[test]
fn prompt_parser_accepts_supported_values_and_rejects_duplicates() {
    let (options, normalized) =
        PromptOptions::parse(Some("login consent")).expect("supported prompt values");
    assert!(options.login && options.consent);
    assert_eq!(normalized.as_deref(), Some("login consent"));
    assert_eq!(
        PromptOptions::parse(Some("login login")).expect_err("duplicate prompt"),
        AuthorizationRequestError::InvalidPrompt
    );
}

#[test]
fn prompt_none_cannot_be_combined_with_interaction() {
    assert_eq!(
        PromptOptions::parse(Some("none login")).expect_err("illegal prompt combination"),
        AuthorizationRequestError::PromptNoneCombined
    );
}

#[test]
fn max_age_zero_always_requires_reauthentication() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(100);
    assert!(!authentication_is_fresh(now, now, Some(0)));
    assert!(authentication_is_fresh(
        now - Duration::seconds(30),
        now,
        Some(30)
    ));
    assert!(!authentication_is_fresh(
        now - Duration::seconds(31),
        now,
        Some(30)
    ));
}

#[test]
fn reauthentication_fence_accepts_a_new_session_for_zero_max_age() {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(100);
    assert!(reauthentication_is_satisfied(
        "new-session",
        Some("old-session"),
        now,
        now,
        Some(0),
        true,
    ));
    assert!(!reauthentication_is_satisfied(
        "old-session",
        Some("old-session"),
        now,
        now,
        Some(0),
        true,
    ));
    assert!(reauthentication_is_satisfied(
        "new-session",
        None,
        now,
        now,
        Some(0),
        true,
    ));
    assert!(!reauthentication_is_satisfied(
        "new-session",
        Some("old-session"),
        now + Duration::seconds(1),
        now,
        Some(0),
        true,
    ));
}
