use super::{VERIFY_BATCH_SIZE, canonical_email_matches};

#[test]
fn verify_batch_size_is_a_positive_page() {
    assert!(VERIFY_BATCH_SIZE > 0);
}

#[test]
fn matching_ascii_row_agrees_with_the_canonicalizer() {
    assert!(canonical_email_matches(
        "User@Example.com",
        "user@example.com"
    ));
}

#[test]
fn wrong_ascii_canonical_is_a_mismatch() {
    // 旧过滤只看域名里有没有 `xn--`，这类行会直接放行。
    assert!(!canonical_email_matches(
        "user@Example.com",
        "user@Example.com"
    ));
}

#[test]
fn local_part_case_difference_is_a_mismatch() {
    assert!(!canonical_email_matches(
        "John.Doe@example.com",
        "John.Doe@example.com"
    ));
}

#[test]
fn unicode_domain_stored_without_punycode_is_a_mismatch() {
    // `lower(email)` 不会做 IDNA，库存会留下 Unicode 域名，旧 SQL 看不见它。
    assert!(!canonical_email_matches(
        "User@ÉXAMPLE.COM",
        "user@éxample.com"
    ));
}

#[test]
fn unicode_display_with_punycode_canonical_matches() {
    assert!(canonical_email_matches(
        "User@ÉXAMPLE.COM",
        "user@xn--xample-9ua.com"
    ));
}

#[test]
fn unparseable_email_is_a_mismatch() {
    assert!(!canonical_email_matches(
        "broken@xn--a-ecp.example",
        "broken@xn--a-ecp.example"
    ));
}
