use chenxing_auth::extensions::{BusinessExtension, EmptyExtension};

#[test]
fn empty_business_extension_does_not_leak_claims() {
    let extension = EmptyExtension;
    assert_eq!(extension.extension_id(), "empty");
    assert!(extension.claims_for_user(42, &[]).is_empty());
}
