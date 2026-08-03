use std::future::Future;

use super::{domain::LoginTicket, service::AuthFactorServiceError};

/// Atomically reserves the one-time ticket before persistence and restores it
/// when the durable write fails. This is the safe orchestration for credentials:
/// a replay cannot write another credential, while a transient database failure
/// leaves the challenge available for a retry.
pub(super) async fn consume_then_persist<C, T, P, R, TE, PE, RF, RE>(
    completed: C,
    invalid: C,
    take: T,
    persist: P,
    restore: R,
) -> Result<C, AuthFactorServiceError>
where
    T: Future<Output = Result<Option<LoginTicket>, TE>>,
    P: Future<Output = Result<(), PE>>,
    R: FnOnce(LoginTicket) -> RF,
    RF: Future<Output = Result<(), RE>>,
    TE: Into<AuthFactorServiceError>,
    PE: Into<AuthFactorServiceError>,
    RE: Into<AuthFactorServiceError>,
{
    let Some(ticket) = take.await.map_err(Into::into)? else {
        return Ok(invalid);
    };
    if let Err(error) = persist.await {
        restore(ticket).await.map_err(Into::into)?;
        return Err(error.into());
    }
    Ok(completed)
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::auth_factors::{
        crypto::SecretCryptoError,
        domain::FactorMethod,
        service::{PasskeyConfirmation, TotpConfirmation},
    };

    #[tokio::test]
    async fn consume_then_persist_restores_ticket_after_persistence_failure() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Passkey]);
        let restored = Arc::new(Mutex::new(None));
        let restored_for_closure = restored.clone();
        let result = consume_then_persist(
            PasskeyConfirmation::Completed(1),
            PasskeyConfirmation::InvalidTicket,
            async { Ok::<_, AuthFactorServiceError>(Some(ticket.clone())) },
            async { Err::<(), _>(AuthFactorServiceError::Secret(SecretCryptoError::Malformed)) },
            move |ticket| {
                let restored = restored_for_closure.clone();
                async move {
                    *restored.lock().unwrap() = Some(ticket);
                    Ok::<_, AuthFactorServiceError>(())
                }
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(AuthFactorServiceError::Secret(SecretCryptoError::Malformed))
        ));
        assert!(restored.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn consume_then_persist_does_not_persist_without_ticket() {
        let persisted = Arc::new(AtomicBool::new(false));
        let persisted_for_future = persisted.clone();
        let result = consume_then_persist(
            TotpConfirmation::Completed(1),
            TotpConfirmation::InvalidTicket,
            async { Ok::<_, AuthFactorServiceError>(None) },
            async move {
                persisted_for_future.store(true, Ordering::SeqCst);
                Ok::<_, AuthFactorServiceError>(())
            },
            |_ticket| async { Ok::<_, AuthFactorServiceError>(()) },
        )
        .await;
        assert!(matches!(result, Ok(TotpConfirmation::InvalidTicket)));
        assert!(!persisted.load(Ordering::SeqCst));
    }
}
