use std::sync::{Arc, Barrier};
use std::time::Duration;

use super::{Argon2Gate, Argon2SpawnError, MAX_ARGON2_CONCURRENCY, default_concurrency};

async fn wait_barrier(barrier: Arc<Barrier>) {
    tokio::task::spawn_blocking(move || {
        barrier.wait();
    })
    .await
    .expect("barrier handshake");
}

#[test]
fn default_concurrency_stays_within_the_hard_cap() {
    let limit = default_concurrency();
    assert!(limit >= 1);
    assert!(limit <= MAX_ARGON2_CONCURRENCY);
}

/// Issue #658：在途 Argon2 不能超过许可数。多路并发挤同一把闸门，
/// 峰值必须被卡住，结束时许可全部归还。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peak_in_flight_never_exceeds_permit_limit() {
    let gate = Arc::new(Argon2Gate::new(2));
    let mut joins = Vec::new();
    for _ in 0..8 {
        let gate = Arc::clone(&gate);
        joins.push(tokio::spawn(async move {
            gate.spawn_blocking(|| {
                std::thread::sleep(Duration::from_millis(15));
                1_u8
            })
            .await
        }));
    }

    for join in joins {
        join.await
            .expect("worker task")
            .expect("bounded argon2 work");
    }

    assert!(gate.peak() <= gate.limit(), "peak {} > limit", gate.peak());
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(gate.available_permits(), gate.limit());
}

/// 关键交错：调用方已经被取消，阻塞闭包还在跑。许可必须留在闭包里，
/// 否则超时请求会把槽位让给下一波，实际并发再次无界。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_caller_does_not_release_permit_before_work_finishes() {
    let gate = Arc::new(Argon2Gate::new(1));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));

    let holder = tokio::spawn({
        let gate = Arc::clone(&gate);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        async move {
            gate.spawn_blocking(move || {
                entered.wait();
                release.wait();
                1_u8
            })
            .await
        }
    });

    wait_barrier(Arc::clone(&entered)).await;
    assert_eq!(gate.in_flight(), 1);
    assert_eq!(gate.available_permits(), 0);

    holder.abort();
    let aborted = holder.await;
    assert!(aborted.is_err(), "caller must be cancelled");

    // 若许可活在 async 侧，abort 会立刻把它放回。给运行时一个窗口暴露这个 bug。
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(gate.in_flight(), 1, "blocking work still holds the slot");
    assert_eq!(gate.available_permits(), 0);

    let waiter = tokio::spawn({
        let gate = Arc::clone(&gate);
        async move { gate.spawn_blocking(|| 2_u8).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        gate.in_flight(),
        1,
        "a waiting caller must not enqueue another Argon2 closure"
    );

    wait_barrier(Arc::clone(&release)).await;
    let waited = waiter
        .await
        .expect("waiter task")
        .expect("permit recovered");
    assert_eq!(waited, 2);
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(gate.available_permits(), 1);
}

/// 排队等许可的调用方被取消时，不得把工作丢进阻塞池。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_waiter_does_not_enqueue_blocking_work() {
    let gate = Arc::new(Argon2Gate::new(1));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));

    let holder = tokio::spawn({
        let gate = Arc::clone(&gate);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        async move {
            gate.spawn_blocking(move || {
                entered.wait();
                release.wait();
            })
            .await
        }
    });

    wait_barrier(Arc::clone(&entered)).await;

    let waiter = tokio::spawn({
        let gate = Arc::clone(&gate);
        async move { gate.spawn_blocking(|| "should not run").await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    waiter.abort();
    assert!(waiter.await.is_err());
    assert_eq!(gate.in_flight(), 1);
    assert_eq!(gate.available_permits(), 0);

    wait_barrier(release).await;
    holder.await.expect("holder task").expect("holder finished");
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(gate.available_permits(), 1);

    let recovered = gate
        .spawn_blocking(|| "recovered")
        .await
        .expect("permit reusable after waiter abort");
    assert_eq!(recovered, "recovered");
}

/// panic 路径也必须归还许可，否则一次坏哈希会永久堵死登录。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_in_work_releases_the_permit() {
    let gate = Argon2Gate::new(1);
    let result = gate
        .spawn_blocking(|| -> u8 {
            panic!("argon2 test panic");
        })
        .await;
    assert!(matches!(result, Err(Argon2SpawnError::Join(_))));
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(gate.available_permits(), 1);

    let recovered = gate
        .spawn_blocking(|| 7_u8)
        .await
        .expect("permit released after panic");
    assert_eq!(recovered, 7);
    assert_eq!(gate.in_flight(), 0);
}

/// 信号量关闭时 fail-closed：不入队，不增加 in-flight。
#[tokio::test]
async fn closed_semaphore_fails_closed_without_spawning() {
    let gate = Argon2Gate::new(1);
    gate.close();
    let result = gate.spawn_blocking(|| 1_u8).await;
    assert!(matches!(result, Err(Argon2SpawnError::Saturated)));
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(gate.available_permits(), 1);
}
