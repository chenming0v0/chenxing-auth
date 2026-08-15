use super::{LimiterPolicy, RedisAuthFailureLimiter};
use crate::{
    auth_limiter::{AuthFailureLimits, AuthLimiterFailurePolicy, FailureDimension},
    redis_client::RedisClient,
    redis_keyspace::RedisKeyspace,
};

fn limiter(namespace: &str) -> RedisAuthFailureLimiter {
    RedisAuthFailureLimiter {
        client: RedisClient::open("redis://127.0.0.1:6379").expect("Redis URL"),
        keyspace: RedisKeyspace::new(namespace).expect("namespace"),
        policy: LimiterPolicy::fixed(
            AuthLimiterFailurePolicy::FailClosed,
            AuthFailureLimits::default(),
        ),
    }
}

#[test]
fn deployment_namespaces_isolate_failure_and_pending_keys() {
    let first = limiter("limiter-a");
    let second = limiter("limiter-b");

    assert_ne!(
        first.failure_key(FailureDimension::Account, "same-account"),
        second.failure_key(FailureDimension::Account, "same-account")
    );
    assert_ne!(
        first.pending_key(FailureDimension::Account, "same-account"),
        second.pending_key(FailureDimension::Account, "same-account")
    );
}
