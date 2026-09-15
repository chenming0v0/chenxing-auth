//! Redis-backed session, authorization-code and refresh-token store lifecycles.

use super::*;

#[tokio::test]
async fn redis_stores_cover_session_and_one_time_token_lifecycles() {
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");

    let sessions = SessionStore::with_redis_key(client.clone(), [0; 32]);
    let mut session =
        Session::new("storage-user".to_owned(), Duration::from_secs(60)).expect("session");
    let watermark_key = "chenxing:session:revoked-before:storage-user".to_owned();
    let _: usize = connection
        .del(&watermark_key)
        .await
        .expect("clear Redis-only session watermark");
    assert!(
        !connection
            .exists::<_, bool>(&watermark_key)
            .await
            .expect("check missing Redis-only session watermark")
    );
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    assert_eq!(
        sessions
            .find(&session.token)
            .await
            .expect("find session")
            .unwrap()
            .id,
        session.id
    );
    let session_hash = session_token_hash_bytes(&session.token);
    let lookup = sessions
        .find_by_token_hash(&session_hash)
        .await
        .expect("find session by hash")
        .expect("hashed session lookup");
    assert_eq!(lookup.id, session.id);
    assert_eq!(lookup.user_id, session.user_id);
    sessions
        .revoke(&session.token)
        .await
        .expect("revoke session");
    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none()
    );
    assert!(
        sessions
            .find_by_token_hash(&session_hash)
            .await
            .expect("find revoked session by hash")
            .is_none()
    );

    let codes = AuthorizationCodeStore::new(client.clone());
    let code = AuthorizationCode::new(
        "storage-client".to_owned(),
        "https://storage.example/callback".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    codes.save(&code).await.expect("save authorization code");
    let code_key = format!(
        "chenxing:oauth:code:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(code.value.as_bytes()))
    );
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let code_payload: String = connection.get(&code_key).await.expect("stored code JSON");
    let mut code_json: serde_json::Value =
        serde_json::from_str(&code_payload).expect("parse code JSON");
    code_json["future_field"] = serde_json::json!({"version": 2});
    let _: () = connection
        .set_ex(
            &code_key,
            serde_json::to_string(&code_json).expect("encode code JSON"),
            60,
        )
        .await
        .expect("inject future code field");
    assert!(codes.find(&code.value).await.expect("find code").is_some());
    let mismatched = AuthorizationCode::new(
        code.client_id.clone(),
        code.redirect_uri.clone(),
        code.user_id.clone(),
        code.scopes.clone(),
        "different-challenge".to_owned(),
    );
    assert!(
        !codes
            .take_if_matches(&code.value, &mismatched)
            .await
            .expect("mismatched code consume")
    );
    assert!(
        codes
            .take_if_matches(&code.value, &code)
            .await
            .expect("matching code consume")
    );
    assert!(
        codes
            .take(&code.value)
            .await
            .expect("take missing code")
            .is_none()
    );
    codes
        .restore(&code, 60)
        .await
        .expect("restore authorization code");
    assert_eq!(
        codes
            .find(&code.value)
            .await
            .expect("find restored code")
            .expect("restored authorization code")
            .value,
        code.value
    );
    codes.take(&code.value).await.expect("remove restored code");

    let refreshes = RefreshTokenStore::new(client.clone());
    let refresh = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    refreshes.save(&refresh).await.expect("save refresh token");
    let refresh_key = format!(
        "chenxing:oauth:refresh:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(refresh.value.as_bytes()))
    );
    let refresh_payload: String = connection
        .get(&refresh_key)
        .await
        .expect("stored refresh JSON");
    let mut refresh_json: serde_json::Value =
        serde_json::from_str(&refresh_payload).expect("parse refresh JSON");
    refresh_json["future_field"] = serde_json::json!(["v2"]);
    let _: () = connection
        .set_ex(
            &refresh_key,
            serde_json::to_string(&refresh_json).expect("encode refresh JSON"),
            60,
        )
        .await
        .expect("inject future refresh field");
    assert!(
        refreshes
            .find(&refresh.value)
            .await
            .expect("find refresh")
            .is_some()
    );
    assert!(
        refreshes
            .take_if_matches(&refresh.value, &refresh)
            .await
            .expect("consume refresh token")
    );
    assert!(
        refreshes
            .find(&refresh.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        refreshes
            .read_tombstone(&refresh.value)
            .await
            .expect("read consumed refresh tombstone")
            .is_some(),
        "consuming a refresh token must leave a replay tombstone"
    );

    let rotatable = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    let rotated = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        rotatable.scopes.clone(),
    );
    let mismatched = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        vec!["profile".to_owned()],
    );
    refreshes
        .save(&rotatable)
        .await
        .expect("save rotatable refresh token");
    assert_eq!(
        refreshes
            .rotate_if_matches(&rotatable.value, &mismatched, &rotated)
            .await
            .expect("mismatched refresh rotation"),
        RotationOutcome::CasMismatch
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find refresh after mismatched rotation")
            .is_some()
    );
    assert_eq!(
        refreshes
            .rotate_if_matches(&rotatable.value, &rotatable, &rotated)
            .await
            .expect("matching refresh rotation"),
        RotationOutcome::Rotated
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        refreshes
            .find(&rotated.value)
            .await
            .expect("find rotated refresh")
            .is_some()
    );
    // 消费后的旧 token 键已不存在（Issue #312）：store 层如实报告键消失，
    // 是重放还是良性消失由用例层结合墓碑判定。
    assert_eq!(
        refreshes
            .rotate_if_matches(
                &rotatable.value,
                &rotatable,
                &RefreshToken::new(
                    rotatable.client_id.clone(),
                    rotatable.user_id.clone(),
                    rotatable.scopes.clone(),
                )
            )
            .await
            .expect("duplicate refresh rotation"),
        RotationOutcome::KeyMissing
    );

    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    let _: usize = connection
        .del(&[
            session_key,
            watermark_key,
            format!(
                "chenxing:oauth:code:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(code.value.as_bytes()))
            ),
            format!("chenxing:oauth:refresh:{}", refresh.value),
            format!("chenxing:oauth:refresh:{}", rotatable.value),
            format!("chenxing:oauth:refresh:{}", rotated.value),
        ])
        .await
        .expect("cleanup Redis keys");
}
