use crate::oauth::request_store::AuthorizationRequestStore;
use crate::sessions::domain::session_token_hash;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PendingRequestBindingError {
    Expired,
    Invalid,
    Storage,
}

pub(crate) async fn bind_pending_request(
    store: &AuthorizationRequestStore,
    request_id: &str,
    session_token: &str,
    holder_hash: Option<&str>,
) -> Result<(), PendingRequestBindingError> {
    let Some(mut pending) = store.find(request_id).await.map_err(|error_value| {
        tracing::error!(
            error = %error_value,
            "failed to load pending authorization request for external login"
        );
        PendingRequestBindingError::Storage
    })?
    else {
        return Err(PendingRequestBindingError::Expired);
    };
    if pending.request_id != request_id {
        return Err(PendingRequestBindingError::Invalid);
    }
    let session_hash = session_token_hash(session_token);
    match (holder_hash, pending.holder_hash.as_deref()) {
        (Some(holder_hash), Some(stored_hash)) if holder_hash == stored_hash => {}
        _ => return Err(PendingRequestBindingError::Invalid),
    }
    match pending.session_token_hash.as_deref() {
        None => {}
        Some(existing) if existing == session_hash => return Ok(()),
        Some(_) => return Err(PendingRequestBindingError::Invalid),
    }
    let original_pending = pending.clone();
    pending.session_token_hash = Some(session_hash.clone());
    match store
        .replace_if_matches(request_id, &original_pending, &pending)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => match store.find(request_id).await {
            Ok(Some(current))
                if current.request_id == request_id
                    && current.session_token_hash.as_deref() == Some(session_hash.as_str()) =>
            {
                Ok(())
            }
            Ok(Some(_)) => Err(PendingRequestBindingError::Invalid),
            Ok(None) => Err(PendingRequestBindingError::Expired),
            Err(error_value) => {
                tracing::error!(
                    error = %error_value,
                    "failed to confirm pending authorization request binding"
                );
                Err(PendingRequestBindingError::Storage)
            }
        },
        Err(error_value) => {
            tracing::error!(
                error = %error_value,
                "failed to bind pending authorization request after external login"
            );
            Err(PendingRequestBindingError::Storage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PendingRequestBindingError, bind_pending_request};
    use crate::oauth::{consent::PendingAuthorization, request_store::AuthorizationRequestStore};
    use crate::sessions::{cookies, domain::session_token_hash};

    fn store() -> AuthorizationRequestStore {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        AuthorizationRequestStore::new(redis::Client::open(url).expect("Redis URL"))
    }

    fn pending(request_id: String, client_id: &str) -> PendingAuthorization {
        PendingAuthorization {
            request_id,
            client_id: client_id.to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_token_hash: None,
            holder_hash: Some(cookies::authz_holder_hash("test-holder")),
        }
    }

    #[tokio::test]
    async fn concurrent_bindings_have_one_winner_and_same_session_retry_is_idempotent() {
        let store = store();
        let request = pending(
            format!("provider-bind-{}", uuid::Uuid::new_v4().simple()),
            &format!("provider-bind-client-{}", uuid::Uuid::new_v4().simple()),
        );
        store.save(&request).await.expect("save pending request");
        let first_store = store.clone();
        let second_store = store.clone();
        let first_session = "session-a";
        let second_session = "session-b";
        let holder_hash = cookies::authz_holder_hash("test-holder");
        let (first, second) = tokio::join!(
            bind_pending_request(
                &first_store,
                &request.request_id,
                first_session,
                Some(holder_hash.as_str()),
            ),
            bind_pending_request(
                &second_store,
                &request.request_id,
                second_session,
                Some(holder_hash.as_str()),
            ),
        );
        let winners = [first, second]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(winners, 1);
        let bound = store
            .find(&request.request_id)
            .await
            .expect("find bound request")
            .expect("bound request");
        let winning_session_hash = bound
            .session_token_hash
            .expect("winning session hash");
        let first_session_hash = session_token_hash(first_session);
        let second_session_hash = session_token_hash(second_session);
        assert!(
            winning_session_hash == first_session_hash
                || winning_session_hash == second_session_hash
        );
        assert_eq!(
            bind_pending_request(
                &store,
                &request.request_id,
                if winning_session_hash == first_session_hash {
                    first_session
                } else {
                    second_session
                },
                Some(holder_hash.as_str()),
            )
            .await,
            Ok(())
        );
        let losing_session = if winning_session_hash == first_session_hash {
            second_session
        } else {
            first_session
        };
        assert_eq!(
            bind_pending_request(
                &store,
                &request.request_id,
                losing_session,
                Some(holder_hash.as_str()),
            )
            .await,
            Err(PendingRequestBindingError::Invalid)
        );
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");

        let same_session_request = pending(
            format!("provider-bind-same-{}", uuid::Uuid::new_v4().simple()),
            &format!(
                "provider-bind-same-client-{}",
                uuid::Uuid::new_v4().simple()
            ),
        );
        store
            .save(&same_session_request)
            .await
            .expect("save same-session pending request");
        let first_store = store.clone();
        let second_store = store.clone();
        let (first, second) = tokio::join!(
            bind_pending_request(
                &first_store,
                &same_session_request.request_id,
                "same-session",
                Some(holder_hash.as_str()),
            ),
            bind_pending_request(
                &second_store,
                &same_session_request.request_id,
                "same-session",
                Some(holder_hash.as_str()),
            ),
        );
        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
        store
            .take(&same_session_request.request_id)
            .await
            .expect("cleanup same-session pending request");
    }

    #[tokio::test]
    async fn binding_without_holder_cookie_is_rejected() {
        let store = store();
        let request = pending(
            format!("provider-bind-no-holder-{}", uuid::Uuid::new_v4().simple()),
            &format!(
                "provider-bind-no-holder-client-{}",
                uuid::Uuid::new_v4().simple()
            ),
        );
        store.save(&request).await.expect("save pending request");

        assert_eq!(
            bind_pending_request(&store, &request.request_id, "session-a", None).await,
            Err(PendingRequestBindingError::Invalid)
        );
        assert_eq!(
            store
                .find(&request.request_id)
                .await
                .expect("find pending request")
                .expect("pending request")
                .session_token_hash,
            None
        );
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }

    #[tokio::test]
    async fn binding_with_mismatched_holder_is_rejected() {
        let store = store();
        let mut request = pending(
            format!("provider-bind-mismatched-holder-{}", uuid::Uuid::new_v4().simple()),
            &format!(
                "provider-bind-mismatched-holder-client-{}",
                uuid::Uuid::new_v4().simple()
            ),
        );
        request.session_token_hash = Some(session_token_hash("session-a"));
        store.save(&request).await.expect("save pending request");
        let mismatched_holder_hash = cookies::authz_holder_hash("other-holder");

        assert_eq!(
            bind_pending_request(
                &store,
                &request.request_id,
                "session-a",
                Some(mismatched_holder_hash.as_str()),
            )
            .await,
            Err(PendingRequestBindingError::Invalid)
        );
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }

    #[tokio::test]
    async fn legacy_pending_request_without_holder_hash_is_rejected() {
        let store = store();
        let mut request = pending(
            format!("provider-bind-legacy-{}", uuid::Uuid::new_v4().simple()),
            &format!(
                "provider-bind-legacy-client-{}",
                uuid::Uuid::new_v4().simple()
            ),
        );
        request.holder_hash = None;
        store.save(&request).await.expect("save pending request");
        let holder_hash = cookies::authz_holder_hash("test-holder");

        assert_eq!(
            bind_pending_request(
                &store,
                &request.request_id,
                "session-a",
                Some(holder_hash.as_str()),
            )
            .await,
            Err(PendingRequestBindingError::Invalid)
        );
        store
            .take(&request.request_id)
            .await
            .expect("cleanup pending request");
    }
}
