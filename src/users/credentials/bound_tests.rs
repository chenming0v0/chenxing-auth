//! Issue #658：真实校验与哑校验必须抢同一把 Argon2 许可。
//!
//! 失败场景：登录洪泛把真实/哑 Argon2 无界丢进阻塞池。超时取消 JoinHandle
//! 不会停掉已经在跑的闭包，于是 CPU、内存和阻塞线程一起被吃光。
//!
//! 这里用测试闸门（上限 = 1）卡住唯一槽位，再并发打真实校验和哑校验：
//! 两者都必须在闸门外排队，不能另开一条 spawn_blocking。许可归还后两条
//! 路径都要跑完 Argon2（哑校验不能被「优化」成快路径），并且 panic/关闭
//! 路径必须把许可放回。

use std::sync::{Arc, Barrier};
use std::time::Duration;

use super::{
    FALLBACK_DUMMY_PASSWORD_HASH,
    gate::{Argon2Gate, Argon2SpawnError, with_gate},
    hash_password, verify_login_password, verify_password,
};

async fn wait_barrier(barrier: Arc<Barrier>) {
    tokio::task::spawn_blocking(move || {
        barrier.wait();
    })
    .await
    .expect("barrier handshake");
}

/// 真实校验、哑校验、哈希共用上限；调用方取消不能在闭包结束前释放槽位。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_and_dummy_verification_share_the_argon2_bound() {
    let gate = Arc::new(Argon2Gate::new(1));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));

    with_gate(Arc::clone(&gate), || {
        let gate = Arc::clone(&gate);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        async move {
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
            assert_eq!(gate.in_flight(), 1);
            assert_eq!(gate.available_permits(), 0);

            let dummy = tokio::spawn({
                let gate = Arc::clone(&gate);
                async move {
                    with_gate(gate, || async {
                        verify_login_password("timing-probe".to_owned(), None).await
                    })
                    .await
                }
            });
            let real = tokio::spawn({
                let gate = Arc::clone(&gate);
                async move {
                    with_gate(gate, || async {
                        verify_password(
                            "timing-probe".to_owned(),
                            FALLBACK_DUMMY_PASSWORD_HASH.to_owned(),
                        )
                        .await
                    })
                    .await
                }
            });
            let hashing = tokio::spawn({
                let gate = Arc::clone(&gate);
                async move {
                    with_gate(gate, || async {
                        hash_password("timing-probe".to_owned()).await
                    })
                    .await
                }
            });

            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                gate.in_flight(),
                1,
                "real, dummy, and hash must wait on the same permit"
            );
            assert_eq!(gate.peak(), 1);

            wait_barrier(release).await;
            holder.await.expect("holder task").expect("holder finished");

            assert!(!dummy.await.expect("dummy task"));
            assert!(!real.await.expect("real verify task"));
            hashing
                .await
                .expect("hash task")
                .expect("hash recovered after the bound opened");

            assert_eq!(gate.in_flight(), 0);
            assert_eq!(gate.available_permits(), 1);
            assert_eq!(gate.peak(), 1);
        }
    })
    .await;
}

/// 闸门关闭时三条口令路径都 fail-closed，且不增加在途 Argon2。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_gate_fails_closed_for_hash_and_both_verifies() {
    let gate = Arc::new(Argon2Gate::new(1));
    gate.close();

    with_gate(Arc::clone(&gate), || {
        let gate = Arc::clone(&gate);
        async move {
            assert!(hash_password("closed-gate".to_owned()).await.is_err());
            assert!(!verify_password("closed-gate".to_owned(), "not-a-phc".to_owned()).await);
            assert!(!verify_login_password("closed-gate".to_owned(), None).await);
            assert_eq!(gate.in_flight(), 0);

            let spawn_result = gate.spawn_blocking(|| 1_u8).await;
            assert!(matches!(spawn_result, Err(Argon2SpawnError::Saturated)));
        }
    })
    .await;
}

/// 许可归还后哑校验仍然付出 Argon2 代价，上限不能把计时填充「优化」掉。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dummy_verify_still_runs_argon2_when_a_permit_is_available() {
    let gate = Arc::new(Argon2Gate::new(1));
    with_gate(gate, || async {
        let started = std::time::Instant::now();
        assert!(!verify_login_password("timing-probe".to_owned(), None).await);
        assert!(
            started.elapsed() >= Duration::from_millis(5),
            "dummy verify must not skip Argon2 when a permit is available"
        );
    })
    .await;
}
