//! [`HarnessBuilder`] 契约的纯内存回归：不连接数据库 / Redis，由 `harness.rs`
//! 在 `#[cfg(test)]` 下引入。

use super::*;

#[test]
fn builder_qps_window_override_defaults_to_disabled() {
    let builder = HarnessBuilder::new("qps-default");

    assert!(
        !builder.qps_window_override,
        "QPS window override must be opt-in so limiting stays observable by default"
    );
}

#[test]
fn builder_qps_window_override_is_opt_in() {
    let builder = HarnessBuilder::new("qps-opt-in").qps_window_override();

    assert!(builder.qps_window_override);
}

#[test]
#[should_panic(expected = "may only be called once")]
fn builder_rejects_repeated_configure_hook() {
    let _ = HarnessBuilder::new("repeated-configure")
        .configure(|_config| {})
        .configure(|_config| {});
}

/// 断言在任何 env / DB I/O 之前触发：若顺序反了，这里会先撞上连接错误而不是
/// 期望的 panic 文案，测试即失败。
#[tokio::test]
#[should_panic(expected = "build_state() must not be combined with bootstrap_owner()")]
async fn build_state_rejects_bootstrap_owner_before_io() {
    let _ = HarnessBuilder::new("reject-bootstrap-owner")
        .bootstrap_owner()
        .build_state()
        .await;
}

#[tokio::test]
#[should_panic(expected = "build_state() must not be combined with isolate_user_ids()")]
async fn build_state_rejects_isolate_user_ids_before_io() {
    let _ = HarnessBuilder::new("reject-isolate-user-ids")
        .isolate_user_ids()
        .build_state()
        .await;
}
