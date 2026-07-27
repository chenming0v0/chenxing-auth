use chenxing_auth::extensions::{BusinessExtension, EmptyExtension};
use uuid::Uuid;

#[test]
fn empty_business_extension_does_not_leak_claims() {
    let extension = EmptyExtension;
    assert_eq!(extension.extension_id(), "empty");
    assert!(extension.claims_for_user(Uuid::new_v4(), &[]).is_empty());
}
