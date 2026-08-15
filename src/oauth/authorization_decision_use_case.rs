//! Authorization-decision application use case, independent of Axum types.

use crate::{
    oauth::{
        authorization::ValidatedAuthorizationRequest,
        authorization_code_handlers::{AuthorizationCodeIssue, AuthorizationCodeIssueError},
        consent::{ConsentDecision, PendingAuthorization},
    },
    users::domain::UserId,
};

#[derive(Debug)]
pub enum AuthorizationDecisionOutcome {
    Approved { redirect_to: String },
    Denied { redirect_to: String },
    QuotaExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationDecisionPortError {
    #[error("authorization request storage is unavailable")]
    StorageUnavailable,
    #[error("the OAuth client is invalid")]
    InvalidClient,
    #[error("the authorization request is invalid")]
    InvalidRequest,
    #[error("session revalidation is unavailable")]
    SessionUnavailable,
    #[error("consent persistence is unavailable")]
    ConsentUnavailable,
    #[error("the consent client disappeared after validation")]
    ConsentClientMissing,
    #[error(transparent)]
    Code(#[from] AuthorizationCodeIssueError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationDecisionError {
    #[error("the authorization request is expired")]
    Expired,
    #[error("the authorization request is not bound to the active session")]
    InvalidSession,
    #[error("the authorization session is no longer active")]
    SessionNoLongerActive,
    #[error(transparent)]
    Port(#[from] AuthorizationDecisionPortError),
}

pub struct AuthorizationDecisionRequest<'a> {
    pub request_id: &'a str,
    pub user_id: UserId,
    pub session_token_hash: &'a str,
    pub decision: ConsentDecision,
    pub source_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

pub(crate) trait AuthorizationDecisionPort {
    async fn find_pending(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationDecisionPortError>;

    async fn take_pending(
        &self,
        request_id: &str,
        expected: &PendingAuthorization,
    ) -> Result<Option<PendingAuthorization>, AuthorizationDecisionPortError>;

    async fn validate_pending(
        &self,
        pending: &PendingAuthorization,
    ) -> Result<ValidatedAuthorizationRequest, AuthorizationDecisionPortError>;

    async fn session_still_active(&self) -> Result<bool, AuthorizationDecisionPortError>;

    async fn save_consent(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<(), AuthorizationDecisionPortError>;

    async fn issue_code(
        &self,
        user_id: UserId,
        validated: ValidatedAuthorizationRequest,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuthorizationCodeIssue, AuthorizationDecisionPortError>;

    async fn restore_pending(&self, pending: &PendingAuthorization);

    async fn record_denied(
        &self,
        user_id: UserId,
        pending: &PendingAuthorization,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    );
}

pub(crate) async fn decide_authorization<P>(
    port: &P,
    request: AuthorizationDecisionRequest<'_>,
) -> Result<AuthorizationDecisionOutcome, AuthorizationDecisionError>
where
    P: AuthorizationDecisionPort + ?Sized,
{
    let Some(pending) = port.find_pending(request.request_id).await? else {
        return Err(AuthorizationDecisionError::Expired);
    };
    if pending.session_token_hash.as_deref() != Some(request.session_token_hash) {
        return Err(AuthorizationDecisionError::InvalidSession);
    }

    if matches!(request.decision, ConsentDecision::Deny) {
        let Some(consumed) = port.take_pending(request.request_id, &pending).await? else {
            return Err(AuthorizationDecisionError::Expired);
        };
        port.record_denied(
            request.user_id,
            &consumed,
            request.source_ip,
            request.user_agent,
        )
        .await;
        let redirect_to =
            error_redirect(&consumed).ok_or(AuthorizationDecisionPortError::InvalidRequest)?;
        return Ok(AuthorizationDecisionOutcome::Denied { redirect_to });
    }

    let validated = port.validate_pending(&pending).await?;
    let Some(consumed) = port.take_pending(request.request_id, &pending).await? else {
        return Err(AuthorizationDecisionError::Expired);
    };
    match port.session_still_active().await {
        Ok(true) => {}
        Ok(false) => {
            port.restore_pending(&consumed).await;
            return Err(AuthorizationDecisionError::SessionNoLongerActive);
        }
        Err(error_value) => {
            port.restore_pending(&consumed).await;
            return Err(error_value.into());
        }
    }
    if let Err(error_value) = port
        .save_consent(request.user_id, &consumed.client_id, &validated.scopes)
        .await
    {
        port.restore_pending(&consumed).await;
        return Err(error_value.into());
    }
    match port
        .issue_code(
            request.user_id,
            validated,
            request.source_ip,
            request.user_agent,
        )
        .await
    {
        Ok(AuthorizationCodeIssue::Redirect(redirect_to)) => {
            Ok(AuthorizationDecisionOutcome::Approved { redirect_to })
        }
        Ok(AuthorizationCodeIssue::QuotaExceeded) => {
            port.restore_pending(&consumed).await;
            Ok(AuthorizationDecisionOutcome::QuotaExceeded)
        }
        Err(error_value) => {
            port.restore_pending(&consumed).await;
            Err(error_value.into())
        }
    }
}

fn error_redirect(pending: &PendingAuthorization) -> Option<String> {
    let mut redirect = url::Url::parse(&pending.redirect_uri).ok()?;
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &pending.state);
    Some(redirect.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone, Copy)]
    enum IssueOutcome {
        Redirect,
        QuotaExceeded,
    }

    struct FakePort {
        pending: PendingAuthorization,
        session_active: bool,
        issue: IssueOutcome,
        restored: Mutex<usize>,
        denied_audits: Mutex<usize>,
    }

    impl AuthorizationDecisionPort for FakePort {
        async fn find_pending(
            &self,
            _request_id: &str,
        ) -> Result<Option<PendingAuthorization>, AuthorizationDecisionPortError> {
            Ok(Some(self.pending.clone()))
        }

        async fn take_pending(
            &self,
            _request_id: &str,
            _expected: &PendingAuthorization,
        ) -> Result<Option<PendingAuthorization>, AuthorizationDecisionPortError> {
            Ok(Some(self.pending.clone()))
        }

        async fn validate_pending(
            &self,
            pending: &PendingAuthorization,
        ) -> Result<ValidatedAuthorizationRequest, AuthorizationDecisionPortError> {
            Ok(ValidatedAuthorizationRequest {
                client_id: pending.client_id.clone(),
                redirect_uri: pending.redirect_uri.clone(),
                scopes: pending
                    .scope
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
                state: pending.state.clone(),
                nonce: pending.nonce.clone(),
                code_challenge: pending.code_challenge.clone(),
                owner_user_id: None,
                session_token_hash: pending.session_token_hash.clone(),
            })
        }

        async fn session_still_active(&self) -> Result<bool, AuthorizationDecisionPortError> {
            Ok(self.session_active)
        }

        async fn save_consent(
            &self,
            _user_id: i64,
            _client_id: &str,
            _scopes: &[String],
        ) -> Result<(), AuthorizationDecisionPortError> {
            Ok(())
        }

        async fn issue_code(
            &self,
            _user_id: i64,
            _validated: ValidatedAuthorizationRequest,
            _source_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) -> Result<AuthorizationCodeIssue, AuthorizationDecisionPortError> {
            Ok(match self.issue {
                IssueOutcome::Redirect => {
                    AuthorizationCodeIssue::Redirect("https://client.example/cb?code=secret".into())
                }
                IssueOutcome::QuotaExceeded => AuthorizationCodeIssue::QuotaExceeded,
            })
        }

        async fn restore_pending(&self, _pending: &PendingAuthorization) {
            *self.restored.lock().expect("restored lock") += 1;
        }

        async fn record_denied(
            &self,
            _user_id: i64,
            _pending: &PendingAuthorization,
            _source_ip: Option<&str>,
            _user_agent: Option<&str>,
        ) {
            *self.denied_audits.lock().expect("audit lock") += 1;
        }
    }

    fn pending() -> PendingAuthorization {
        PendingAuthorization {
            request_id: "request-1".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/cb".to_owned(),
            scope: "openid profile".to_owned(),
            state: "state-1".to_owned(),
            nonce: Some("nonce-1".to_owned()),
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: Some("session-hash".to_owned()),
            holder_hash: None,
        }
    }

    fn port(session_active: bool, issue: IssueOutcome) -> FakePort {
        FakePort {
            pending: pending(),
            session_active,
            issue,
            restored: Mutex::new(0),
            denied_audits: Mutex::new(0),
        }
    }

    #[tokio::test]
    async fn deny_consumes_pending_and_returns_pure_redirect_result() {
        let port = port(true, IssueOutcome::Redirect);

        let outcome = decide_authorization(
            &port,
            AuthorizationDecisionRequest {
                request_id: "request-1",
                user_id: 42,
                session_token_hash: "session-hash",
                decision: ConsentDecision::Deny,
                source_ip: Some("192.0.2.1"),
                user_agent: Some("test-agent"),
            },
        )
        .await
        .expect("deny decision should complete");

        assert!(matches!(
            outcome,
            AuthorizationDecisionOutcome::Denied { ref redirect_to }
                if redirect_to.contains("error=access_denied")
        ));
        assert_eq!(*port.denied_audits.lock().expect("audit lock"), 1);
        assert_eq!(*port.restored.lock().expect("restored lock"), 0);
    }

    #[tokio::test]
    async fn quota_failure_restores_consumed_pending_request() {
        let port = port(true, IssueOutcome::QuotaExceeded);

        let outcome = decide_authorization(
            &port,
            AuthorizationDecisionRequest {
                request_id: "request-1",
                user_id: 42,
                session_token_hash: "session-hash",
                decision: ConsentDecision::Approve,
                source_ip: None,
                user_agent: None,
            },
        )
        .await
        .expect("quota result is an application outcome");

        assert!(matches!(
            outcome,
            AuthorizationDecisionOutcome::QuotaExceeded
        ));
        assert_eq!(*port.restored.lock().expect("restored lock"), 1);
    }

    #[tokio::test]
    async fn inactive_session_after_consume_restores_pending_request() {
        let port = port(false, IssueOutcome::Redirect);

        let error = decide_authorization(
            &port,
            AuthorizationDecisionRequest {
                request_id: "request-1",
                user_id: 42,
                session_token_hash: "session-hash",
                decision: ConsentDecision::Approve,
                source_ip: None,
                user_agent: None,
            },
        )
        .await
        .expect_err("inactive session must block authorization");

        assert!(matches!(
            error,
            AuthorizationDecisionError::SessionNoLongerActive
        ));
        assert_eq!(*port.restored.lock().expect("restored lock"), 1);
    }
}
