use chenxing_auth::auth_factors::{
    domain::{FactorMethod, LoginTicket},
    store::LoginTicketStore,
};
use redis::AsyncCommands;
use std::sync::Arc;

fn redis_client() -> redis::Client {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

#[tokio::test]
async fn login_ticket_is_readable_then_consumed_once() {
    let client = redis_client();
    let store = LoginTicketStore::new(client.clone());
    let holder_hash = "holder-hash".to_owned();
    let (ticket_id, ticket) = store
        .create_with_holder(42, vec![FactorMethod::Totp], holder_hash.clone())
        .await
        .expect("create ticket");

    assert_eq!(
        store
            .find_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("find ticket")
            .map(|value| value.user_id),
        Some(ticket.user_id)
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take ticket")
            .is_some()
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take consumed ticket")
            .is_none()
    );

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = connection
        .del(format!("chenxing:auth:login-ticket:{ticket_id}"))
        .await
        .expect("cleanup ticket");
}

#[tokio::test]
async fn login_ticket_cannot_be_read_or_consumed_with_another_holder() {
    let client = redis_client();
    let store = LoginTicketStore::new(client.clone());
    let holder_hash = "holder-a".to_owned();
    let (ticket_id, _) = store
        .create_with_holder(42, vec![FactorMethod::Totp], holder_hash.clone())
        .await
        .expect("create ticket");

    assert!(
        store
            .find_for_holder(&ticket_id, "holder-b")
            .await
            .expect("find with wrong holder")
            .is_none()
    );
    assert!(
        store
            .take_for_holder(&ticket_id, "holder-b")
            .await
            .expect("take with wrong holder")
            .is_none()
    );
    assert!(
        store
            .take_for_holder(&ticket_id, &holder_hash)
            .await
            .expect("take with correct holder")
            .is_some()
    );

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = connection
        .del(LoginTicketStore::key(&ticket_id))
        .await
        .expect("cleanup ticket");
}

#[test]
fn login_ticket_serializes_without_secrets() {
    let ticket = LoginTicket::new(42, vec![FactorMethod::Passkey]);
    let json = serde_json::to_value(ticket).expect("ticket JSON");
    assert!(json.get("user_id").is_some());
    assert!(json.get("methods").is_some());
    assert!(json.get("secret").is_none());
}

/// #265：`save_json_if_absent` 是键的唯一预留入口，并发只允许一个写入者。
///
/// 断言两件事，缺一不可：胜者数量恰好为 1，且键里留下的是胜者的载荷。
/// 只数胜者不够——先查后写的实现同样可能只让一个调用「看起来」成功，
/// 却被后到的写入覆盖了内容。
#[tokio::test]
async fn only_one_concurrent_writer_reserves_an_absent_json_key() {
    let client = redis_client();
    let store = Arc::new(LoginTicketStore::new(client.clone()));
    let key = format!("chenxing:auth:test-reserve:{}", uuid::Uuid::new_v4());
    let mut tasks = Vec::new();
    for candidate in 0..12_u32 {
        let store = store.clone();
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            let stored = store
                .save_json_if_absent(&key, &candidate, 60)
                .await
                .expect("reserve JSON key");
            (candidate, stored)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (candidate, stored) = task.await.expect("join reservation");
        if stored {
            winners.push(candidate);
        }
    }
    assert_eq!(winners.len(), 1, "exactly one writer may reserve the key");

    assert_eq!(
        store
            .find_json::<u32>(&key)
            .await
            .expect("read reserved payload"),
        Some(winners[0]),
        "the reserved payload must belong to the single winner"
    );

    // 键已被占用：后续预留一律失败，且绝不改写已有载荷。
    assert!(
        !store
            .save_json_if_absent(&key, &9_999_u32, 60)
            .await
            .expect("reserve occupied key")
    );
    assert_eq!(
        store
            .find_json::<u32>(&key)
            .await
            .expect("read payload after losing reservation"),
        Some(winners[0]),
        "a losing reservation must not overwrite the stored payload"
    );

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let ttl: i64 = connection.ttl(&key).await.expect("reserved key TTL");
    assert!(
        ttl > 0 && ttl <= 60,
        "reservation must carry the requested TTL, got {ttl}"
    );

    // 键被释放后可以重新预留：预留是一次性占用，不是永久锁。
    store.delete(&key).await.expect("release reservation");
    assert!(
        store
            .save_json_if_absent(&key, &7_u32, 60)
            .await
            .expect("reserve released key")
    );
    assert_eq!(
        store
            .find_json::<u32>(&key)
            .await
            .expect("read re-reserved payload"),
        Some(7)
    );

    let _: usize = connection.del(&key).await.expect("cleanup reservation");
}

#[tokio::test]
async fn one_totp_time_step_can_be_claimed_only_once_across_tickets() {
    let client = redis_client();
    let store = Arc::new(LoginTicketStore::new(client.clone()));
    let user_id = uuid::Uuid::new_v4().as_u128() as i64;
    let timestep = 56_666_666_u64;
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .claim_totp_timestep(user_id, timestep)
                .await
                .expect("claim TOTP timestep")
        }));
    }
    let mut claimed = 0;
    for task in tasks {
        claimed += u8::from(task.await.expect("join TOTP claim"));
    }
    assert_eq!(claimed, 1);
    assert!(
        store
            .claim_totp_timestep(user_id, timestep + 1)
            .await
            .expect("claim adjacent TOTP timestep")
    );

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: usize = connection
        .del(vec![
            LoginTicketStore::totp_replay_key(user_id, timestep),
            LoginTicketStore::totp_replay_key(user_id, timestep + 1),
        ])
        .await
        .expect("cleanup TOTP claims");
}
