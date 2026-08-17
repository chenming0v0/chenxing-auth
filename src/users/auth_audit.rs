use crate::{audit::AuditEvent, state::AppState};

pub(super) async fn record_security_event(
    state: &AppState,
    action: crate::audit::AuditAction,
    actor_id: Option<crate::users::domain::UserId>,
    reason: &str,
    attempted_identifier: Option<&str>,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) {
    state
        .audit
        .record_best_effort(AuditEvent::authentication_failure(
            action,
            if actor_id.is_some() {
                "user".to_owned()
            } else {
                "anonymous".to_owned()
            },
            actor_id.map(|id| id.to_string()),
            "authentication".to_owned(),
            None,
            reason,
            attempted_identifier,
            source_ip,
            user_agent,
        ))
        .await;
}
