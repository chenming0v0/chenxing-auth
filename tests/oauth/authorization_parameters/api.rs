use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header::LOCATION},
    response::Response,
};
use chenxing_auth::sessions::domain::Session;
use url::Url;

use crate::{
    harness::{Harness, HarnessBuilder, suffix},
    http, oauth_flow,
};

const REDIRECT_URI: &str = "https://disabled.example/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Fixture {
    harness: Harness,
    client_id: String,
    cookie: String,
}

async fn fixture(label: &str) -> Fixture {
    let harness = HarnessBuilder::new(label)
        .bootstrap_owner()
        .qps_window_override()
        .build()
        .await;
    let (user_id, _, _, _) = oauth_flow::register_test_user(&harness.router, &suffix()).await;
    let (client_id, _) =
        oauth_flow::create_test_client(&harness.router, &harness.admin_token).await;
    chenxing_auth::sqlx::query(
        "INSERT INTO user_consents (user_id, client_id, scopes, updated_at)
         SELECT $1, id, $3, $4 FROM oauth_clients WHERE client_id = $2",
    )
    .bind(user_id)
    .bind(&client_id)
    .bind(serde_json::json!(["openid"]))
    .bind(harness.state.clock.now())
    .execute(&harness.database)
    .await
    .expect("save existing consent");
    let mut session = Session::new(user_id.to_string(), std::time::Duration::from_secs(3600))
        .expect("browser session");
    harness
        .state
        .sessions
        .save(&mut session, std::time::Duration::from_secs(3600))
        .await
        .expect("persist browser session");
    Fixture {
        harness,
        client_id,
        cookie: oauth_flow::session_cookie(&session),
    }
}

async fn authorize(
    fixture: &Fixture,
    method: Method,
    client_id: &str,
    redirect_uri: &str,
    extra: &str,
) -> Response {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", "parameter-state")
        .append_pair("code_challenge", CHALLENGE)
        .append_pair("code_challenge_method", "S256");
    let mut form = form.finish();
    if !extra.is_empty() {
        form.push('&');
        form.push_str(extra);
    }
    let builder = Request::builder()
        .method(method.clone())
        .header("accept", "text/html")
        .header("cookie", &fixture.cookie);
    let request = if method == Method::GET {
        builder
            .uri(format!("/oauth/authorize?{form}"))
            .body(Body::empty())
    } else {
        builder
            .uri("/oauth/authorize")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form))
    }
    .expect("authorization request");
    http::send(&fixture.harness.router, request).await
}

#[tokio::test]
async fn get_and_post_reject_unsupported_parameters_before_issuing_a_code() {
    let fixture = fixture("oauth_authorization_parameter_errors").await;
    for method in [Method::GET, Method::POST] {
        for (extra, expected) in [
            ("response_mode=fragment", "invalid_request"),
            ("response_mode=form_post", "invalid_request"),
            ("request=opaque-jwt", "request_not_supported"),
            (
                "request_uri=https%3A%2F%2Fclient.example%2Frequest.jwt",
                "request_uri_not_supported",
            ),
        ] {
            let response = authorize(
                &fixture,
                method.clone(),
                &fixture.client_id,
                REDIRECT_URI,
                extra,
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let redirect = Url::parse(&http::location(&response)).expect("verified callback");
            assert_eq!(
                redirect.origin().ascii_serialization(),
                "https://disabled.example"
            );
            let parameters = redirect
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(
                parameters.get("error").map(|value| value.as_ref()),
                Some(expected)
            );
            assert_eq!(
                parameters.get("state").map(|value| value.as_ref()),
                Some("parameter-state"),
            );
            assert!(!parameters.contains_key("code"));
            assert!(redirect.fragment().is_none());
            assert!(response.headers().get("set-cookie").is_none());
        }
    }
    fixture.harness.cleanup().await;
}

#[tokio::test]
async fn get_and_post_keep_query_authorization_and_unknown_parameters_supported() {
    let fixture = fixture("oauth_authorization_parameter_success").await;
    let metadata = http::get(
        &fixture.harness.router,
        "/.well-known/openid-configuration",
        &[],
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = http::json_body(metadata).await;
    assert_eq!(
        metadata["response_modes_supported"],
        serde_json::json!(["query"])
    );
    assert_eq!(metadata["request_parameter_supported"], false);
    assert_eq!(metadata["request_uri_parameter_supported"], false);

    for method in [Method::GET, Method::POST] {
        for extra in [
            "",
            "response_mode=query",
            "response_mode=&request=&request_uri=",
            "vendor_hint=preferred",
        ] {
            let response = authorize(
                &fixture,
                method.clone(),
                &fixture.client_id,
                REDIRECT_URI,
                extra,
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let redirect = Url::parse(&http::location(&response)).expect("authorization callback");
            let code = redirect
                .query_pairs()
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.into_owned())
                .expect("authorization code");
            let stored = fixture
                .harness
                .state
                .authorization_codes
                .take(&code)
                .await
                .expect("read authorization code")
                .expect("authorization code was stored");
            assert_eq!(stored.client_id, fixture.client_id);
            assert_eq!(stored.redirect_uri, REDIRECT_URI);
        }
    }
    fixture.harness.cleanup().await;
}

#[tokio::test]
async fn unsupported_parameters_never_redirect_invalid_clients_or_unregistered_callbacks() {
    let fixture = fixture("oauth_authorization_parameter_redirects").await;
    for method in [Method::GET, Method::POST] {
        for (client_id, redirect_uri, expected) in [
            ("cx_missing_client", REDIRECT_URI, "invalid_client"),
            (
                fixture.client_id.as_str(),
                "https://attacker.example/callback",
                "invalid_request",
            ),
        ] {
            for extra in [
                "request=opaque-jwt",
                "request_uri=opaque-uri",
                "response_mode=fragment",
            ] {
                let response =
                    authorize(&fixture, method.clone(), client_id, redirect_uri, extra).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert!(response.headers().get(LOCATION).is_none());
                let error = http::json_body(response).await;
                assert_eq!(error["error"], expected);
                assert!(error.get("code").is_none());
            }
        }
    }
    fixture.harness.cleanup().await;
}
