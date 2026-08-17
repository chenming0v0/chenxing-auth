//! Revoke-consent application use case, independent of Axum request/response types.

use crate::{
    audit::{AuditEvent, AuditService},
    consents::ConsentService,
    oauth::{refresh_store::RefreshTokenStore, revocation::TokenRevocationStore},
    users::domain::UserId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeConsentOutcome {
    AlreadyRevoked,
    Revoked {
        state_version: i64,
        revoked_refresh_tokens: Option<u64>,
    },
}

pub struct RevokeConsentServices<'a> {
    pub consents: &'a ConsentService,
    pub refresh_tokens: &'a RefreshTokenStore,
    pub revocations: &'a TokenRevocationStore,
    pub audit: &'a AuditService,
}

pub(crate) trait RevokeConsentPort {
    async fn revoke_authoritative(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<i64>, crate::sqlx::Error>;

    async fn revoke_refresh_tokens(&self, subject: &str, client_id: &str) -> Option<u64>;

    async fn publish_revocation(&self, subject: &str, client_id: &str, state_version: i64);

    async fn record_revocation(
        &self,
        subject: &str,
        client_id: &str,
        revoked_refresh_tokens: Option<u64>,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    );
}

impl RevokeConsentPort for RevokeConsentServices<'_> {
    async fn revoke_authoritative(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<i64>, crate::sqlx::Error> {
        self.consents.revoke_for_user(user_id, client_id).await
    }

    async fn revoke_refresh_tokens(&self, subject: &str, client_id: &str) -> Option<u64> {
        match self
            .refresh_tokens
            .revoke_grant_tokens(subject, client_id)
            .await
        {
            Ok(revoked) => Some(revoked),
            Err(error) => {
                tracing::error!(error = %error, user_id = subject, client_id, "failed to destroy refresh tokens after OAuth consent revocation");
                None
            }
        }
    }

    async fn publish_revocation(&self, subject: &str, client_id: &str, state_version: i64) {
        if let Err(error) = self
            .revocations
            .revoke_consent(subject, client_id, state_version)
            .await
        {
            tracing::warn!(error = %error, user_id = subject, client_id, "failed to update OAuth consent revocation cache");
        }
    }

    async fn record_revocation(
        &self,
        subject: &str,
        client_id: &str,
        revoked_refresh_tokens: Option<u64>,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) {
        self.audit
            .record_best_effort(AuditEvent::new(
                "user".to_owned(),
                Some(subject.to_owned()),
                crate::audit::AuditAction::ConsentRevoke,
                "oauth_consent".to_owned(),
                Some(client_id.to_owned()),
                crate::audit::with_request_context(
                    serde_json::json!({
                        "result": "success",
                        "revoked_refresh_tokens": revoked_refresh_tokens,
                    }),
                    source_ip,
                    user_agent,
                ),
            ))
            .await;
    }
}

pub async fn revoke_consent(
    services: RevokeConsentServices<'_>,
    user_id: UserId,
    client_id: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<RevokeConsentOutcome, crate::sqlx::Error> {
    revoke_consent_with_port(&services, user_id, client_id, source_ip, user_agent).await
}

pub(crate) async fn revoke_consent_with_port<P>(
    port: &P,
    user_id: UserId,
    client_id: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<RevokeConsentOutcome, crate::sqlx::Error>
where
    P: RevokeConsentPort + ?Sized,
{
    let Some(state_version) = port.revoke_authoritative(user_id, client_id).await? else {
        return Ok(RevokeConsentOutcome::AlreadyRevoked);
    };
    let subject = user_id.to_string();
    let revoked_refresh_tokens = port.revoke_refresh_tokens(&subject, client_id).await;
    port.publish_revocation(&subject, client_id, state_version)
        .await;
    port.record_revocation(
        &subject,
        client_id,
        revoked_refresh_tokens,
        source_ip,
        user_agent,
    )
    .await;
    Ok(RevokeConsentOutcome::Revoked {
        state_version,
        revoked_refresh_tokens,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct FakePort {
        state_version: Option<i64>,
        revoked_refresh_tokens: Option<u64>,
        published: Mutex<Vec<i64>>,
        audited: Mutex<Vec<Option<u64>>>,
    }

    impl RevokeConsentPort for FakePort {
        async fn revoke_authoritative(
            &self,
            _user_id: UserId,
            _client_id: &str,
        ) -> Result<Option<i64>, crate::sqlx::Error> {
            Ok(self.state_version)
        }

        async fn revoke_refresh_tokens(&self, _subject: &str, _client_id: &str) -> Option<u64> {
            self.revoked_refresh_tokens
        }

        async fn publish_revocation(&self, _subject: &str, _client_id: &str, state_version: i64) {
            self.published
                .lock()
                .expect("published lock")
                .push(state_version);
        }

        async fn record_revocation(
            &self,
            _subject: &str,
            _client_id: &str,
            revoked_refresh_tokens: Option<u64>,
            _source_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) {
            self.audited
                .lock()
                .expect("audit lock")
                .push(revoked_refresh_tokens);
        }
    }

    fn port(state_version: Option<i64>, revoked_refresh_tokens: Option<u64>) -> FakePort {
        FakePort {
            state_version,
            revoked_refresh_tokens,
            published: Mutex::new(Vec::new()),
            audited: Mutex::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn already_revoked_stops_before_best_effort_side_effects() {
        let port = port(None, Some(3));

        let outcome = revoke_consent_with_port(&port, 42, "client-1", None, None)
            .await
            .expect("already revoked consent is idempotent");

        assert_eq!(outcome, RevokeConsentOutcome::AlreadyRevoked);
        assert!(port.published.lock().expect("published lock").is_empty());
        assert!(port.audited.lock().expect("audit lock").is_empty());
    }

    #[tokio::test]
    async fn successful_revocation_returns_authoritative_version_and_cleanup_count() {
        let port = port(Some(9), Some(3));

        let outcome =
            revoke_consent_with_port(&port, 42, "client-1", Some("192.0.2.1"), Some("test-agent"))
                .await
                .expect("revocation should complete");

        assert_eq!(
            outcome,
            RevokeConsentOutcome::Revoked {
                state_version: 9,
                revoked_refresh_tokens: Some(3),
            }
        );
        assert_eq!(*port.published.lock().expect("published lock"), vec![9]);
        assert_eq!(*port.audited.lock().expect("audit lock"), vec![Some(3)]);
    }
}
