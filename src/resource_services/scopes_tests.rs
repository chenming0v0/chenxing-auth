use super::scopes::{ProviderScope, ScopeCatalogItem, ScopeSource, filter_scopes};
use super::types::ScopeAccess;

fn base() -> Vec<String> {
    ["openid", "profile", "email"]
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect()
}

fn provider(slug: &str, scope: &str, access: ScopeAccess, clients: &[&str]) -> ProviderScope {
    ProviderScope {
        provider_id: uuid::Uuid::new_v4(),
        scope: scope.to_owned(),
        slug: slug.to_owned(),
        display_name: slug.to_uppercase(),
        description: format!("{slug} description"),
        access,
        allowed_client_ids: clients.iter().map(|id| (*id).to_owned()).collect(),
    }
}

#[test]
fn public_scopes_are_visible_to_every_client_and_to_unregistered_apps() {
    let providers = vec![provider("term", "term:access", ScopeAccess::Public, &[])];
    assert_eq!(
        filter_scopes(&base(), &providers, None),
        vec!["openid", "profile", "email", "term:access"]
    );
    assert_eq!(
        filter_scopes(&base(), &providers, Some("anyone")),
        vec!["openid", "profile", "email", "term:access"]
    );
}

#[test]
fn restricted_scopes_are_only_visible_to_listed_clients() {
    let providers = vec![provider(
        "term",
        "term:access",
        ScopeAccess::Restricted,
        &["cx_listed"],
    )];
    assert_eq!(filter_scopes(&base(), &providers, None), base());
    assert_eq!(filter_scopes(&base(), &providers, Some("cx_other")), base());
    assert_eq!(
        filter_scopes(&base(), &providers, Some("cx_listed")),
        vec!["openid", "profile", "email", "term:access"]
    );
}

#[test]
fn services_are_sorted_by_slug_after_base_and_deduplicated() {
    let providers = vec![
        provider("zeta", "zeta:access", ScopeAccess::Public, &[]),
        provider("alpha", "alpha:access", ScopeAccess::Public, &[]),
        provider("dup", "email", ScopeAccess::Public, &[]),
    ];
    assert_eq!(
        filter_scopes(&base(), &providers, None),
        vec!["openid", "profile", "email", "alpha:access", "zeta:access"]
    );
}

#[test]
fn catalog_items_serialize_to_the_frontend_shape() {
    let item = ScopeCatalogItem {
        scope: "term:access".to_owned(),
        title: "Term".to_owned(),
        description: "desc".to_owned(),
        source: ScopeSource::ResourceService,
        access: Some(ScopeAccess::Restricted),
        provider_slug: Some("term".to_owned()),
    };
    assert_eq!(
        serde_json::to_value(&item).expect("serialize"),
        serde_json::json!({
            "scope": "term:access",
            "title": "Term",
            "description": "desc",
            "source": "resource_service",
            "access": "restricted",
            "provider_slug": "term",
        })
    );
    let base_item = ScopeCatalogItem {
        scope: "openid".to_owned(),
        title: "身份标识".to_owned(),
        description: "x".to_owned(),
        source: ScopeSource::Base,
        access: None,
        provider_slug: None,
    };
    let value = serde_json::to_value(&base_item).expect("serialize");
    assert_eq!(value["source"], "base");
    assert!(value["access"].is_null());
    assert!(value["provider_slug"].is_null());
}
