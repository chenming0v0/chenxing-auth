use std::time::Duration;

use chenxing_auth::redis_client::RedisClient;
use redis::{Client, RedisResult};
use tokio::task::JoinSet;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

#[tokio::test]
async fn cloned_clients_share_one_connection_for_concurrent_commands() {
    const COMMAND_COUNT: usize = 32;

    let client = RedisClient::open(redis_url()).expect("Redis URL");
    let mut commands = JoinSet::new();
    for _ in 0..COMMAND_COUNT {
        let client = client.clone();
        commands.spawn(async move {
            let mut connection = client
                .get_multiplexed_async_connection()
                .await
                .expect("managed Redis connection");
            redis::cmd("CLIENT")
                .arg("ID")
                .query_async::<i64>(&mut connection)
                .await
                .expect("Redis connection ID")
        });
    }

    let mut connection_ids = Vec::with_capacity(COMMAND_COUNT);
    while let Some(result) = commands.join_next().await {
        connection_ids.push(result.expect("concurrent Redis command task"));
    }

    assert_eq!(connection_ids.len(), COMMAND_COUNT);
    assert!(
        connection_ids
            .iter()
            .all(|connection_id| *connection_id == connection_ids[0]),
        "all commands should use the same multiplexed TCP connection"
    );
}

#[tokio::test]
async fn dropped_shared_connection_is_replaced() {
    let redis_url = redis_url();
    let client = RedisClient::open(redis_url.as_str()).expect("Redis URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("managed Redis connection");
    let original_id: i64 = redis::cmd("CLIENT")
        .arg("ID")
        .query_async(&mut connection)
        .await
        .expect("original Redis connection ID");

    let killer = Client::open(redis_url).expect("Redis URL");
    let mut killer_connection = killer
        .get_multiplexed_async_connection()
        .await
        .expect("killer Redis connection");
    let killed: i64 = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("ID")
        .arg(original_id)
        .query_async(&mut killer_connection)
        .await
        .expect("kill managed Redis connection");
    assert_eq!(killed, 1);

    let replacement_id = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let result: RedisResult<i64> = redis::cmd("CLIENT")
                .arg("ID")
                .query_async(&mut connection)
                .await;
            if let Ok(connection_id) = result
                && connection_id != original_id
            {
                break connection_id;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("managed Redis connection should recover after disconnect");

    assert_ne!(replacement_id, original_id);
}
