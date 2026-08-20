use std::future::Future;

use super::{domain::LoginTicket, service::AuthFactorServiceError};

/// Atomically reserves the one-time ticket before persistence and restores it
/// when the durable write fails. This is the safe orchestration for credentials:
/// a replay cannot write another credential, while a transient database failure
/// leaves the challenge available for a retry.
///
/// Redis take is destructive and the epoch lookup lives *inside* take. This
/// helper never sees the ticket when take returns `Err`, so a metadata lookup
/// failure must restore before take returns; otherwise a retry finds nothing
/// even though no factor or session write happened. Epoch mismatch is the
/// opposite: take returns `Ok(None)` and the ticket stays consumed so a
/// revoked epoch cannot be replayed.
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

/// After Redis has already taken a one-time ticket, decide whether it stays
/// consumed.
///
/// - `Ok(true)`: metadata still matches; the caller may persist.
/// - `Ok(false)`: known-stale (epoch mismatch or the user is gone). Leave the
///   ticket consumed so a revoked epoch cannot be replayed.
/// - `Err(_)`: infrastructure failure. No durable write happened, so restore
///   the ticket for retry. Lookup failure is not a security rejection.
pub(super) async fn accept_or_restore_taken_ticket<C, CF, R, RF, RE, E>(
    ticket: LoginTicket,
    check: C,
    restore: R,
) -> Result<Option<LoginTicket>, E>
where
    C: FnOnce(&LoginTicket) -> CF,
    CF: Future<Output = Result<bool, E>>,
    R: FnOnce(LoginTicket) -> RF,
    RF: Future<Output = Result<(), RE>>,
    RE: Into<E>,
{
    let outcome = check(&ticket).await;
    match outcome {
        Ok(true) => Ok(Some(ticket)),
        Ok(false) => Ok(None),
        Err(error) => {
            restore(ticket).await.map_err(Into::into)?;
            Err(error)
        }
    }
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
    use crate::users::domain::AuthenticatedUser;

    #[tokio::test]
    async fn consume_then_persist_restores_ticket_after_persistence_failure() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Passkey]);
        let restored = Arc::new(Mutex::new(None));
        let restored_for_closure = restored.clone();
        let result = consume_then_persist(
            PasskeyConfirmation::Completed(AuthenticatedUser::new(1, 0)),
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
            TotpConfirmation::Completed(AuthenticatedUser::new(1, 0)),
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

    #[tokio::test]
    async fn consume_then_persist_keeps_ticket_consumed_after_success() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Totp]);
        let restored = Arc::new(AtomicBool::new(false));
        let restored_for_closure = restored.clone();
        let result = consume_then_persist(
            TotpConfirmation::Completed(AuthenticatedUser::new(1, 0)),
            TotpConfirmation::InvalidTicket,
            async { Ok::<_, AuthFactorServiceError>(Some(ticket)) },
            async { Ok::<_, AuthFactorServiceError>(()) },
            move |_ticket| {
                let restored = restored_for_closure.clone();
                async move {
                    restored.store(true, Ordering::SeqCst);
                    Ok::<_, AuthFactorServiceError>(())
                }
            },
        )
        .await;
        assert!(matches!(result, Ok(TotpConfirmation::Completed(_))));
        assert!(
            !restored.load(Ordering::SeqCst),
            "a successful install must leave the ticket consumed"
        );
    }

    #[tokio::test]
    async fn lookup_failure_after_take_restores_ticket_for_retry() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Totp]);
        let restored = Arc::new(Mutex::new(None));
        let restored_for_closure = restored.clone();
        let result = accept_or_restore_taken_ticket(
            ticket.clone(),
            |_| async { Err::<bool, _>(AuthFactorServiceError::UserNotFound) },
            move |ticket| {
                let restored = restored_for_closure.clone();
                async move {
                    *restored.lock().unwrap() = Some(ticket);
                    Ok::<_, AuthFactorServiceError>(())
                }
            },
        )
        .await;
        assert!(matches!(result, Err(AuthFactorServiceError::UserNotFound)));
        assert!(
            restored.lock().unwrap().is_some(),
            "a metadata lookup failure must restore the taken ticket"
        );
    }

    #[tokio::test]
    async fn epoch_mismatch_after_take_leaves_ticket_consumed() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Totp]);
        let restored = Arc::new(AtomicBool::new(false));
        let restored_for_closure = restored.clone();
        let result = accept_or_restore_taken_ticket(
            ticket,
            |_| async { Ok::<_, AuthFactorServiceError>(false) },
            move |_ticket| {
                let restored = restored_for_closure.clone();
                async move {
                    restored.store(true, Ordering::SeqCst);
                    Ok::<_, AuthFactorServiceError>(())
                }
            },
        )
        .await
        .expect("known-stale epoch is not an infrastructure error");
        assert!(result.is_none());
        assert!(
            !restored.load(Ordering::SeqCst),
            "a known-stale epoch must not restore a replayable ticket"
        );
    }

    #[tokio::test]
    async fn matching_epoch_after_take_returns_ticket_without_restore() {
        let ticket = LoginTicket::new(1, vec![FactorMethod::Totp]);
        let restored = Arc::new(AtomicBool::new(false));
        let restored_for_closure = restored.clone();
        let result = accept_or_restore_taken_ticket(
            ticket,
            |_| async { Ok::<_, AuthFactorServiceError>(true) },
            move |_ticket| {
                let restored = restored_for_closure.clone();
                async move {
                    restored.store(true, Ordering::SeqCst);
                    Ok::<_, AuthFactorServiceError>(())
                }
            },
        )
        .await
        .expect("matching epoch");
        assert!(result.is_some());
        assert!(!restored.load(Ordering::SeqCst));
    }
}
