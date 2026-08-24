use crate::db_isolation::schema_name;

#[test]
fn schema_name_includes_binary_and_test_identity() {
    let result = schema_name("my-binary", "oauth::authorize");

    assert!(result.starts_with("ctest_my_binary_oauth__authorize_"));
    assert_eq!(result.len(), "ctest_my_binary_oauth__authorize_".len() + 16);
}

#[test]
fn schema_name_distinguishes_long_common_prefixes() {
    assert_ne!(
        schema_name(
            "bootstrap_invariant",
            "concurrent_external_identity_creation_rejects_duplicate_email"
        ),
        schema_name(
            "bootstrap_invariant",
            "concurrent_external_identity_creation_reuses_the_same_identity"
        )
    );
}

#[test]
fn schema_name_replaces_non_alphanumeric_characters() {
    let result = schema_name("my-binary", "test/name::case");

    assert!(result.starts_with("ctest_my_binary_test_name__case_"));
    assert!(
        result
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    );
}

#[test]
fn schema_name_truncates_to_63_bytes() {
    let result = schema_name(&"binary".repeat(20), &"test".repeat(20));

    assert_eq!(result.len(), 63);
    assert!(result.starts_with("ctest_binary"));
}
