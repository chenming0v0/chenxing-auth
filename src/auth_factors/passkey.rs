use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use super::{
    AuthFactorService, AuthFactorServiceError, PasskeyConfirmation,
};
use crate::auth_factors::{
    domain::{FactorMethod, LoginTicket},
    persistence::persist_then_consume,
    repository,
};

const PASSKEY_REGISTRATION_PREFIX: &str = "chenxing:auth:passkey-registration:";
const PASSKEY_AUTHENTICATION_PREFIX: &str = "chenxing:auth:passkey-authentication:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyRegistration {
    user_id: i64,
    state: PasskeyRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyAuthentication {
    user_id: i64,
    state: PasskeyAuthentication,
}

impl AuthFactorService {
    pub async fn start_passkey_registration(
        &self,
        ticket_id: &str,
        user_name: &str,
        display_name: &str,
    ) -> Result<Option<webauthn_rs::prelude::CreationChallengeResponse>, AuthFactorServiceError>
    {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
            || !repository::list_factor_methods(&self.pool, ticket.user_id)
                .await?
                .is_empty()
        {
            return Ok(None);
        }
        let existing = repository::list_passkeys(&self.pool, ticket.user_id).await?;
        let exclude = Some(
            existing
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect(),
        );
        let (challenge, state) = self.webauthn.start_passkey_registration(
            Uuid::from_u128(ticket.user_id as u128),
            user_name,
            display_name,
            exclude,
        )?;
        self.tickets
            .save_json(
                &Self::passkey_registration_key(ticket_id),
                &PendingPasskeyRegistration {
                    user_id: ticket.user_id,
                    state,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(challenge))
    }

    pub async fn finish_passkey_registration(
        &self,
        ticket_id: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyRegistration>(&Self::passkey_registration_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        let passkey = match self
            .webauthn
            .finish_passkey_registration(credential, &pending.state)
        {
            Ok(passkey) => passkey,
            Err(_) => return Ok(PasskeyConfirmation::InvalidCredential),
        };
        if matches!(
            repository::insert_passkey(&self.pool, ticket.user_id, passkey.cred_id(), &passkey)
                .await?,
            repository::PasskeyPersistenceResult::Conflict
        ) {
            return Ok(PasskeyConfirmation::InvalidCredential);
        }
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        self.tickets
            .delete(&Self::passkey_registration_key(ticket_id))
            .await?;
        Ok(PasskeyConfirmation::Completed(ticket.user_id))
    }

    pub async fn start_passkey_authentication(
        &self,
        ticket_id: &str,
    ) -> Result<Option<RequestChallengeResponse>, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(None);
        }
        let passkeys = repository::list_passkeys(&self.pool, ticket.user_id).await?;
        if passkeys.is_empty() {
            return Ok(None);
        }
        let (challenge, state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        self.tickets
            .save_json(
                &Self::passkey_authentication_key(ticket_id),
                &PendingPasskeyAuthentication {
                    user_id: ticket.user_id,
                    state,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(challenge))
    }

    pub async fn finish_passkey_authentication(
        &self,
        ticket_id: &str,
        credential: &PublicKeyCredential,
    ) -> Result<PasskeyConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Passkey)
        {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingPasskeyAuthentication>(&Self::passkey_authentication_key(ticket_id))
            .await?
        else {
            return Ok(PasskeyConfirmation::InvalidTicket);
        };
        let result = match self
            .webauthn
            .finish_passkey_authentication(credential, &pending.state)
        {
            Ok(result) => result,
            Err(_) => return Ok(PasskeyConfirmation::InvalidCredential),
        };
        let mut passkeys = repository::list_passkeys(&self.pool, ticket.user_id).await?;
        let Some(passkey) = passkeys
            .iter_mut()
            .find(|passkey| passkey.cred_id() == result.cred_id())
        else {
            return Ok(PasskeyConfirmation::InvalidCredential);
        };
        let confirmation = persist_then_consume(
            PasskeyConfirmation::Completed(ticket.user_id),
            PasskeyConfirmation::InvalidTicket,
            async {
                if result.needs_update()
                    && passkey
                        .update_credential(&result)
                        .is_some_and(|changed| changed)
                {
                    repository::update_passkey(&self.pool, result.cred_id(), passkey).await?;
                }
                Ok::<(), AuthFactorServiceError>(())
            },
            self.tickets.take(ticket_id),
        )
        .await?;
        self.tickets
            .delete(&Self::passkey_authentication_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

    fn passkey_registration_key(ticket_id: &str) -> String {
        format!("{PASSKEY_REGISTRATION_PREFIX}{ticket_id}")
    }

    fn passkey_authentication_key(ticket_id: &str) -> String {
        format!("{PASSKEY_AUTHENTICATION_PREFIX}{ticket_id}")
    }
}
