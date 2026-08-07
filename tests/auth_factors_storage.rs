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
    assert!(store
        .take_for_holder(&ticket_id, &holder_hash)
        .await
        .expect("take ticket")
        .is_some());
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

    assert!(store
        .find_for_holder(&ticket_id, "holder-b")
        .await
        .expect("find with wrong holder")
        .is_none());
    assert!(store
        .take_for_holder(&ticket_id, "holder-b")
        .await
        .expect("take with wrong holder")
        .is_none());
    assert!(store
        .take_for_holder(&ticket_id, &holder_hash)
        .await
        .expect("take with correct holder")
        .is_some());

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
