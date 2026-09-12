#![allow(dead_code)]

//! `email_change_outbox` 拆分后的共享夹具：邮件发送器替身、登录态与请求助手。

use std::sync::{Arc, Mutex};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chenxing_auth::{
    api,
    notifications::{EmailMessage, EmailSender},
    sqlx::PgPool,
    state::AppState,
};
use tokio::sync::Notify;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{harness, http, oauth_flow};

pub const PASSWORD: &str = "correct horse battery";

#[derive(Clone, Default)]
pub struct CapturingSender {
    messages: Arc<Mutex<Vec<EmailMessage>>>,
}

#[derive(Clone, Default)]
pub struct FailingSender;

impl EmailSender for FailingSender {
    fn send<'a>(
        &'a self,
        _message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(chenxing_auth::notifications::EmailSendError::Delivery) })
    }
}

impl CapturingSender {
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.messages.lock().expect("sender lock").clone()
    }
}

impl EmailSender for CapturingSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        let messages = self.messages.clone();
        Box::pin(async move {
            messages.lock().expect("sender lock").push(message);
            Ok(())
        })
    }
}

#[derive(Clone, Default)]
pub struct BlockingSender {
    pub messages: Arc<Mutex<Vec<EmailMessage>>>,
    pub started: Arc<Notify>,
    pub release: Arc<Notify>,
    first_send: Arc<Mutex<bool>>,
    database: Option<PgPool>,
}

impl BlockingSender {
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.messages.lock().expect("sender lock").clone()
    }

    pub fn with_database(mut self, database: PgPool) -> Self {
        self.database = Some(database);
        self
    }
}

impl EmailSender for BlockingSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), chenxing_auth::notifications::EmailSendError>,
                > + Send
                + 'a,
        >,
    > {
        let messages = self.messages.clone();
        let started = self.started.clone();
        let release = self.release.clone();
        let database = self.database.clone();
        let should_block = {
            let mut first_send = self.first_send.lock().expect("sender lock");
            if *first_send {
                false
            } else {
                *first_send = true;
                true
            }
        };
        Box::pin(async move {
            if let Some(database) = database {
                chenxing_auth::sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(&database)
                    .await
                    .map_err(|_| chenxing_auth::notifications::EmailSendError::Delivery)?;
            }
            if should_block {
                started.notify_one();
                release.notified().await;
                messages.lock().expect("sender lock").push(message);
                Ok(())
            } else {
                Err(chenxing_auth::notifications::EmailSendError::Delivery)
            }
        })
    }
}

pub async fn start_request(
    router: &axum::Router,
    cookie: &str,
    email: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/email-change/start")
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-csrf-token", http::cookie_value(cookie, "chenxing_csrf"))
                .body(Body::from(
                    serde_json::json!({
                        "new_email": email,
                        "current_password": PASSWORD,
                    })
                    .to_string(),
                ))
                .expect("email change request"),
        )
        .await
        .expect("email change response")
}

pub async fn start_challenge(router: &axum::Router, cookie: &str, email: &str) -> Uuid {
    let response = start_request(router, cookie, email).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("email change response body");
    serde_json::from_slice::<serde_json::Value>(&body)
        .expect("email change response json")["challenge_id"]
        .as_str()
        .expect("challenge id")
        .parse()
        .expect("uuid challenge id")
}

pub fn verification_code(messages: &[EmailMessage]) -> String {
    messages
        .iter()
        .find(|message| message.subject == "辰星通行证邮箱变更验证码")
        .and_then(|message| message.body.split('：').nth(1))
        .and_then(|code| code.split('\n').next())
        .map(str::to_owned)
        .expect("verification code message")
}

pub async fn logged_in_state(
    binary_name: &str,
) -> (
    AppState,
    PgPool,
    std::path::PathBuf,
    String,
    CapturingSender,
) {
    logged_in_state_with_max_connections(binary_name, 4).await
}

pub async fn logged_in_state_with_max_connections(
    binary_name: &str,
    max_connections: u32,
) -> (
    AppState,
    PgPool,
    std::path::PathBuf,
    String,
    CapturingSender,
) {
    let (state, database, key_directory, _admin_token, binary_name) =
        harness::HarnessBuilder::new(binary_name)
            .max_connections(max_connections)
            // 原 `oauth_flow::test_state_with_max_connections` 会放大 QPS 窗口，保持一致。
            .qps_window_override()
            .build_state()
            .await;
    let sender = CapturingSender::default();
    let state = state.with_email_sender(Arc::new(sender.clone()));
    let router = api::router(state.clone());
    oauth_flow::ensure_owner_bootstrapped(&router, &database, &binary_name, "email-change-owner")
        .await;
    let (_user_id, username, _email, _password) =
        oauth_flow::register_test_user(&router, "email-change-user").await;
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"identifier": username, "password": PASSWORD}).to_string(),
                ))
                .expect("login request"),
        )
        .await
        .expect("login response");
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = oauth_flow::cookie_header(&login);
    (state, database, key_directory, cookie, sender)
}
