//! Pure contract tests for the shared template database support (#710).
//!
//! These never touch a database and never mutate the process environment: every
//! namespace and configuration is built through the explicit `new` /
//! `from_values` constructors. The only source-scan assertion pins the existing
//! sequence algorithm preserved by the new fixture path.

use crate::db_isolation::template_database::config::url_selects_database;
use crate::db_isolation::template_database::names::quote_identifier;
use crate::db_isolation::template_database::{
    DatabaseName, DbTestError, Namespace, TemplateConfig,
};
use crate::db_isolation::{schema_name, user_id_sequence_start};

const DB_LIFECYCLE: &str = include_str!("../support/template_database/lifecycle.rs");
const DB_CLONE: &str = include_str!("../support/template_database/clone.rs");
const LIFECYCLE_HELPERS: &str = include_str!("template_lifecycle/helpers.rs");
const LIFECYCLE_CLEANUP: &str = include_str!("template_lifecycle/cleanup.rs");
const LIFECYCLE_TRACKING: &str = include_str!("template_lifecycle/tracking.rs");

fn namespace() -> Namespace {
    Namespace::new("ctest_abc123_template", "ctest_abc123_").expect("valid namespace")
}

fn max_prefix() -> String {
    format!("ctest_a{}9_", "b".repeat(27))
}

#[test]
fn namespace_prefix_bounds_and_grammar_are_frozen() {
    // Minimum length is 12 bytes (token length 5).
    let min_prefix = "ctest_a1234_";
    assert_eq!(min_prefix.len(), 12);
    assert!(Namespace::new(&format!("{min_prefix}template"), min_prefix).is_ok());

    // Maximum length is 36 bytes (token length 29).
    let max_prefix = max_prefix();
    assert_eq!(max_prefix.len(), 36);
    assert!(Namespace::new(&format!("{max_prefix}template"), &max_prefix).is_ok());

    for too_short in ["ctest_a12_", "ctest_abc_"] {
        assert!(Namespace::new(&format!("{too_short}template"), too_short).is_err());
    }
    let too_long = format!("ctest_a{}9_", "b".repeat(28));
    assert_eq!(too_long.len(), 37);
    assert!(Namespace::new(&format!("{too_long}template"), &too_long).is_err());

    for token in ["Abcdef", "_abcde", "abcde_", "abc-def", "abc def", "abcéfg"] {
        let prefix = format!("ctest_{token}_");
        assert!(
            Namespace::new(&format!("{prefix}template"), &prefix).is_err(),
            "prefix token {token:?} must be rejected"
        );
    }

    // The prefix must not be normalized: surrounding whitespace is a different,
    // invalid prefix rather than a trimmed valid one.
    assert!(Namespace::new("ctest_abc123_template", " ctest_abc123_ ").is_err());
}

#[test]
fn namespace_requires_exact_template_relationship() {
    let namespace = namespace();
    assert_eq!(namespace.prefix(), "ctest_abc123_");
    assert_eq!(namespace.template_name().as_str(), "ctest_abc123_template");

    for template in [
        "ctest_abc123_templat",
        "ctest_abc123_Template",
        "ctest_abc124_template",
        "ctest_abc123_template_extra",
    ] {
        assert!(Namespace::new(template, "ctest_abc123_").is_err());
    }
}

#[test]
fn clone_names_are_canonical_distinct_and_bounded() {
    let namespace = namespace();
    let first = namespace
        .clone_name("api", "suite::case", 4242)
        .expect("clone");
    let same = namespace
        .clone_name("api", "suite::case", 4242)
        .expect("clone");
    let other_pid = namespace
        .clone_name("api", "suite::case", 4243)
        .expect("clone");
    let other_identity = namespace
        .clone_name("api", "suite::other", 4242)
        .expect("clone");

    assert_eq!(first.as_str(), same.as_str());
    assert_ne!(first.as_str(), other_pid.as_str());
    assert_ne!(first.as_str(), other_identity.as_str());
    assert!(first.as_str().starts_with(namespace.prefix()));
    assert!(namespace.is_copy_name(first.as_str()));

    // The suffix is 16 lowercase hex, an underscore, then the canonical PID.
    let suffix = first
        .as_str()
        .strip_prefix(namespace.prefix())
        .expect("prefix");
    let (hex, pid) = suffix.split_once('_').expect("hash_pid");
    assert_eq!(hex.len(), 16);
    assert!(
        hex.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(pid, "4242");

    // The longest legal prefix plus the widest PID still fits 63 bytes.
    let longest = Namespace::new(&format!("{}template", max_prefix()), &max_prefix())
        .expect("max namespace")
        .clone_name("label", "identity", u32::MAX)
        .expect("clone");
    assert!(longest.as_str().len() <= 63);
    assert!(namespace.clone_name("api", "case", 0).is_err());
}

#[test]
fn copy_name_grammar_rejects_lookalikes() {
    let namespace = namespace();
    let exact = namespace.clone_name("api", "case", 7).expect("clone");
    let prefix = namespace.prefix();
    let hex = "0123456789abcdef";

    assert!(namespace.is_copy_name(exact.as_str()));
    assert!(!namespace.is_copy_name("ctest_abc123_template"));
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}")));
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}_7_extra")));
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}_007")));
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}_+7")));
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}_7.0")));
    assert!(!namespace.is_copy_name(&format!("{prefix}0123456789ABCDEF_7")));
    assert!(!namespace.is_copy_name(&format!("{prefix}0123456789abcde_7")));
    assert!(!namespace.is_copy_name(&format!("{prefix}0123456789abcdef0_7")));
    assert!(!namespace.is_copy_name(&format!("{prefix}%_7")));
    assert!(!namespace.is_copy_name(&format!("ctest_abc124_{hex}_7")));
    // A name that only starts with the prefix must never match.
    assert!(!namespace.is_copy_name(&format!("{prefix}{hex}_7_suffix")));
}

#[test]
fn source_name_protection_matches_template_and_copy_sets() {
    let namespace = namespace();
    let clone = namespace.clone_name("api", "case", 7).expect("clone");

    assert!(namespace.validate_source_name("chenxing_auth_dev").is_ok());
    assert!(namespace.validate_source_name("postgres").is_ok());
    assert_eq!(
        namespace.validate_source_name(namespace.template_name().as_str()),
        Err(DbTestError::ProtectedDatabase)
    );
    assert_eq!(
        namespace.validate_source_name(clone.as_str()),
        Err(DbTestError::ProtectedDatabase)
    );
    assert!(namespace.validate_source_name("").is_err());
    assert!(namespace.validate_source_name(&"x".repeat(64)).is_err());
}

#[test]
fn identifier_quoting_escapes_quotes_and_injection() {
    assert_eq!(quote_identifier("plain"), "\"plain\"");
    assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
    let injected = "x\"; DROP DATABASE y; --";
    assert_eq!(quote_identifier(injected), "\"x\"\"; DROP DATABASE y; --\"");
    // The frozen grammar cannot produce a name containing a quote.
    let namespace = namespace();
    let clone = namespace
        .clone_name("api\"; DROP", "case", 7)
        .expect("clone");
    assert!(!clone.as_str().contains('"'));
}

#[test]
fn source_url_requires_explicit_database_and_protects_the_namespace() {
    let namespace = namespace();
    let clone = namespace.clone_name("api", "case", 7).expect("clone");
    let template = namespace.template_name().as_str().to_owned();

    assert!(
        TemplateConfig::from_values(
            namespace.clone(),
            "postgres://alice@db.example/plain_source",
            None,
        )
        .is_ok()
    );

    // No database component: the driver would otherwise default to a username.
    assert!(
        TemplateConfig::from_values(namespace.clone(), "postgres://alice@db.example", None)
            .is_err()
    );
    assert!(TemplateConfig::from_values(namespace.clone(), "not a url", None).is_err());
    assert!(
        TemplateConfig::from_values(
            namespace.clone(),
            &format!("postgres://alice@db.example/{template}"),
            None,
        )
        .is_err()
    );
    assert!(
        TemplateConfig::from_values(
            namespace.clone(),
            &format!("postgres://alice@db.example/{}", clone.as_str()),
            None,
        )
        .is_err()
    );

    // A runtime URL that names a copy is rejected, never used as a fallback.
    assert!(
        TemplateConfig::from_values(
            namespace.clone(),
            "postgres://alice@db.example/plain_source",
            Some(&format!("postgres://alice@db.example/{}", clone.as_str())),
        )
        .is_err()
    );
}

#[test]
fn source_url_validation_preserves_credentials_and_options() {
    let config = TemplateConfig::from_values(
        namespace(),
        "postgres://alice:secret@db.example:5433/plain_source?options=-c%20search_path%3Dpublic",
        None,
    )
    .expect("valid source");

    let options = config.owner_options_for("clone_db").expect("clone options");
    assert_eq!(options.get_username(), "alice");
    assert_eq!(options.get_host(), "db.example");
    assert_eq!(options.get_port(), 5433);
    assert_eq!(options.get_database(), Some("clone_db"));
    assert_eq!(options.get_options(), Some("-c search_path=public"));
}

#[test]
fn errors_never_leak_urls_or_credentials() {
    let namespace = namespace();
    let clone = namespace.clone_name("api", "case", 7).expect("clone");
    let url = format!("postgres://alice:supersecret@db.example/{}", clone.as_str());
    let error = TemplateConfig::from_values(namespace, &url, None)
        .err()
        .expect("copy source must fail");

    assert_eq!(error, DbTestError::ProtectedDatabase);
    for rendered in [error.to_string(), format!("{error:?}")] {
        for secret in ["supersecret", "db.example", "alice", "postgres://"] {
            assert!(
                !rendered.contains(secret),
                "error leaked {secret:?}: {rendered}"
            );
        }
    }
}

#[test]
fn existing_schema_and_sequence_algorithms_are_unchanged() {
    assert_eq!(
        schema_name("api", "suite::case"),
        schema_name("api", "suite::case")
    );
    assert_ne!(
        schema_name("api", "suite::case"),
        schema_name("api", "suite::other")
    );
    assert!(schema_name("api", "suite::case").starts_with("ctest_api_suite__case_"));
    assert!(schema_name("api", "suite::case").len() <= 63);

    let start = user_id_sequence_start("api", "suite::case-pid-42");
    assert_eq!(start, user_id_sequence_start("api", "suite::case-pid-42"));
    assert_ne!(start, user_id_sequence_start("api", "suite::other-pid-42"));
    assert!((1_000_000..1_000_000 + 1_000_000_000_000).contains(&start));
}

#[test]
fn database_name_validation_is_bounded() {
    assert!(DatabaseName::new_validated("ok_name").is_ok());
    assert!(DatabaseName::new_validated("").is_err());
    assert!(DatabaseName::new_validated(&"x".repeat(64)).is_err());
    assert!(DatabaseName::new_validated("bad\0name").is_err());
}

#[test]
fn url_selector_is_required_and_query_overrides_path() {
    // Explicit path selector.
    assert!(url_selects_database("postgres://alice@db.example/plain_source").is_ok());
    // Explicit `dbname` query selector.
    assert!(url_selects_database("postgres://alice@db.example?dbname=plain_source").is_ok());
    // Both present: the query wins in SQLx, but syntactically both are selectors.
    assert!(url_selects_database("postgres://alice@db.example/plain?dbname=other").is_ok());

    // Missing / empty selectors must be rejected even with PGDATABASE ambient.
    for url in [
        "postgres://alice@db.example",
        "postgres://alice@db.example/",
        "postgres://alice@db.example?dbname=",
        "postgres:///?host=/var/run/postgresql",
        "not a url",
    ] {
        assert!(
            url_selects_database(url).is_err(),
            "URL without a selector must be rejected: {url}"
        );
    }
}

#[test]
fn query_selector_selects_and_protects_the_final_source() {
    let namespace = namespace();
    let clone = namespace.clone_name("api", "case", 7).expect("clone");
    let template = namespace.template_name().as_str().to_owned();

    // Query selector alone picks the final source.
    let config = TemplateConfig::from_values(
        namespace.clone(),
        "postgres://alice@db.example?dbname=plain_source",
        None,
    )
    .expect("query selector");
    assert_eq!(config.source_name().as_str(), "plain_source");

    // Path names the template but `dbname` overrides to a safe database: the
    // final SQLx selector is what gets validated, so this is accepted.
    let safe = format!("postgres://alice@db.example/{template}?dbname=plain_source");
    let config = TemplateConfig::from_values(namespace.clone(), &safe, None)
        .expect("query overrides the path");
    assert_eq!(config.source_name().as_str(), "plain_source");

    // Path is safe but `dbname` overrides to a copy: the final selector is
    // protected.
    let attack = format!(
        "postgres://alice@db.example/plain_source?dbname={}",
        clone.as_str()
    );
    let error = TemplateConfig::from_values(namespace.clone(), &attack, None)
        .err()
        .expect("copy final selector must fail");
    assert_eq!(error, DbTestError::ProtectedDatabase);

    // The same protection applies to the optional runtime URL.
    assert!(
        TemplateConfig::from_values(
            namespace,
            "postgres://alice@db.example/plain_source",
            Some(&attack),
        )
        .is_err()
    );
}

#[test]
fn clone_requires_a_sealed_owned_template_before_creating() {
    let verify = DB_CLONE
        .find("pub(crate) async fn verify_template_sealed")
        .expect("sealed template check");
    let create = DB_CLONE
        .find("CREATE DATABASE {} TEMPLATE {}")
        .expect("create clone statement");
    assert!(
        verify < create,
        "the sealed template check must run before CREATE DATABASE"
    );
    for marker in ["datallowconn", "datistemplate", "datdba"] {
        assert!(
            DB_CLONE.contains(marker),
            "the sealed template check is missing {marker}"
        );
    }
    assert!(
        DB_CLONE.contains("database_error(\"create clone\""),
        "duplicate create must surface as the create-clone operation"
    );
    // Generic cleanup must still remove a partially prepared, unfrozen
    // template: it must not require the sealed state.
    assert!(
        !DB_LIFECYCLE.contains("datallowconn"),
        "generic cleanup must not require the template to be sealed"
    );
    assert!(
        DB_CLONE.contains("template is not prepared"),
        "an absent template must still fail before CREATE"
    );
}

#[test]
fn admin_owner_connection_pins_pg_catalog_before_identity_checks() {
    let pin = DB_LIFECYCLE
        .find("SET search_path TO pg_catalog")
        .expect("admin search_path pin");
    let current = DB_LIFECYCLE
        .find("SELECT current_database()")
        .expect("current_database check");
    let role = DB_LIFECYCLE
        .find("SELECT session_user = current_user")
        .expect("session_user check");
    assert!(
        pin < current && pin < role,
        "the admin connection must pin pg_catalog before any identity query"
    );
}

#[test]
fn finalizer_never_runs_broad_namespace_cleanup() {
    // The finalizer must depend only on successful-create records and must
    // never call `own.cleanup()`, which would delete pre-existing databases even
    // when nothing was created.
    let finalizer = LIFECYCLE_HELPERS
        .split("pub(super) async fn cleanup_owned")
        .nth(1)
        .expect("finalizer present");
    assert!(
        !finalizer.contains("own.cleanup"),
        "the finalizer must not call own.cleanup()"
    );
    assert!(
        finalizer.contains("created.is_empty()"),
        "the finalizer must return early with no tracked records"
    );
    assert!(
        finalizer.contains("drop_tracked"),
        "the finalizer must drop only OID-tracked objects"
    );

    // Every deliberate namespace cleanup lives in the preflighted scenario, and
    // each call is immediately preceded by a catalog preflight.
    let segments: Vec<&str> = LIFECYCLE_CLEANUP.split("own.cleanup().await").collect();
    assert!(
        segments.len() >= 2,
        "the deliberate own.cleanup() calls are missing"
    );
    for segment in &segments[..segments.len() - 1] {
        assert!(
            segment.contains("verify_cleanup_candidates_owned"),
            "each own.cleanup() must be preceded by the catalog preflight"
        );
    }

    // The preflight reads the whole catalog and compares against records; it
    // must not narrow the candidate set with a WHERE clause or a name filter.
    let body = LIFECYCLE_TRACKING
        .split("pub(super) async fn verify_cleanup_candidates_owned")
        .nth(1)
        .expect("preflight helper present");
    let query = body
        .split("FROM pg_catalog.pg_database")
        .next()
        .expect("catalog query present");
    assert!(
        !query.contains("WHERE"),
        "the cleanup preflight must scan the full catalog, not a filtered name"
    );
    assert!(
        body.contains("is_copy_name"),
        "the preflight must reuse the namespace grammar predicates"
    );
}
