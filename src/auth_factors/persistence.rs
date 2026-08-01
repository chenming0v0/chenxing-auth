use std::future::Future;

use super::{
    domain::LoginTicket,
    service::{AuthFactorServiceError, TotpConfirmation},
};
use crate::users::domain::UserId;

/// Persist first, then consume the one-time login ticket. A persistence failure
/// must leave the ticket usable for a retry.
pub(super) async fn persist_then_consume<P, T, PE, TE>(
    user_id: UserId,
    persist: P,
    take: T,
) -> Result<TotpConfirmation, AuthFactorServiceError>
where
    P: Future<Output = Result<(), PE>>,
    T: Future<Output = Result<Option<LoginTicket>, TE>>,
    PE: Into<AuthFactorServiceError>,
    TE: Into<AuthFactorServiceError>,
{
    persist.await.map_err(Into::into)?;
    if take.await.map_err(Into::into)?.is_none() {
        return Ok(TotpConfirmation::InvalidTicket);
    }
    Ok(TotpConfirmation::Completed(user_id))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::auth_factors::{crypto::SecretCryptoError, domain::FactorMethod};

    #[tokio::test]
    async fn persistence_failure_does_not_consume_ticket() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Totp]);
        let consumed = Arc::new(AtomicBool::new(false));
        let take_consumed = consumed.clone();
        let persist =
            async { Err::<(), _>(AuthFactorServiceError::Secret(SecretCryptoError::Malformed)) };
        let take = async move {
            take_consumed.store(true, Ordering::SeqCst);
            Ok::<_, AuthFactorServiceError>(Some(ticket))
        };

        let result = persist_then_consume(1, persist, take).await;
        assert!(matches!(
            result,
            Err(AuthFactorServiceError::Secret(SecretCryptoError::Malformed))
        ));
        assert!(!consumed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn successful_persistence_consumes_ticket_after_persist() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let persist_order = order.clone();
        let take_order = order.clone();
        let persist = async move {
            persist_order.lock().unwrap().push("persist");
            Ok::<(), AuthFactorServiceError>(())
        };
        let take = async move {
            take_order.lock().unwrap().push("take");
            Ok::<_, AuthFactorServiceError>(Some(LoginTicket::new(1, vec![FactorMethod::Totp])))
        };

        let result = persist_then_consume(1, persist, take).await;
        assert!(matches!(result, Ok(TotpConfirmation::Completed(1))));
        assert_eq!(*order.lock().unwrap(), ["persist", "take"]);
    }

    #[tokio::test]
    async fn already_consumed_ticket_returns_invalid_ticket() {
        let result =
            persist_then_consume(1, async { Ok::<(), AuthFactorServiceError>(()) }, async {
                Ok::<_, AuthFactorServiceError>(None)
            })
            .await;
        assert!(matches!(result, Ok(TotpConfirmation::InvalidTicket)));
    }
}
