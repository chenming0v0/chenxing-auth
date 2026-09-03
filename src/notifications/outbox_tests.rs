use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    notifications::{EmailMessage, EmailSendError, EmailSender},
    users::email::EmailAddress,
    workers::WorkerName,
};

use super::*;

struct DelayedSender {
    delay: Duration,
}

impl EmailSender for DelayedSender {
    fn send<'a>(
        &'a self,
        _message: EmailMessage,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), EmailSendError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            Ok(())
        })
    }
}

fn message(subject: &str) -> EmailMessage {
    EmailMessage {
        to: EmailAddress::parse("worker-health@example.com").expect("valid email"),
        subject: subject.to_owned(),
        body: "redacted fixture".to_owned(),
    }
}

#[tokio::test(start_paused = true)]
async fn heartbeat_covers_slow_smtp_and_multi_message_batches() {
    let sender = DelayedSender {
        delay: Duration::from_secs(11),
    };
    let heartbeats = AtomicUsize::new(0);
    let batch = async {
        sender.send(message("first")).await.expect("first send");
        sender.send(message("second")).await.expect("second send");
    };

    heartbeat_while(batch, WORKER_HEARTBEAT_INTERVAL, || {
        heartbeats.fetch_add(1, Ordering::Relaxed);
    })
    .await;

    assert_eq!(heartbeats.load(Ordering::Relaxed), 4);
}

#[test]
fn email_health_and_batch_budgets_cover_valid_work_without_hiding_stalls() {
    let policy = WorkerName::EmailOutbox.policy();
    assert!(policy.heartbeat_timeout > EMAIL_SEND_TIMEOUT);
    assert!(policy.success_timeout > policy.heartbeat_timeout);
    assert!(WORKER_HEARTBEAT_INTERVAL < policy.heartbeat_timeout);

    assert!(worker_batch_has_capacity(2, Duration::from_secs(4)));
    assert!(!worker_batch_has_capacity(2, WORKER_BATCH_TIME_BUDGET));
    assert!(!worker_batch_has_capacity(
        WORKER_BATCH_ENTRY_LIMIT,
        Duration::ZERO
    ));
}
