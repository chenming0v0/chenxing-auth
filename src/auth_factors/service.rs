use crate::users::domain::UserId;
use redis::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::{config::AuthEncryptionKey, sqlx::PgPool};

use super::{
    crypto::{SecretCryptoError, decrypt_totp_secret},
    domain::{FactorMethod, LoginTicket},
    persistence::persist_then_consume,
    repository,
    store::{LoginTicketStore, LoginTicketStoreError},
    totp::{TotpEnrollment, verify_totp_code_current},
};

const TOTP_SETUP_PREFIX: &str = "chenxing:auth:totp-setup:";
const PASSKEY_REGISTRATION_PREFIX: &str = "chenxing:auth:passkey-registration:";
const PASSKEY_AUTHENTICATION_PREFIX: &str = "chenxing:auth:passkey-authentication:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTotpSetup {
    user_id: UserId,
    encrypted_secret: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyRegistration {
    user_id: UserId,
    state: PasskeyRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyAuthentication {
    user_id: UserId,
    state: PasskeyAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpConfirmation {
    InvalidTicket,
    InvalidCode,
    Completed(UserId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyConfirmation {
    InvalidTicket,
    InvalidCredential,
    Completed(UserId),
}

#[derive(Clone)]
pub struct AuthFactorService {
    pool: PgPool,
    tickets: LoginTicketStore,
    encryption_key: AuthEncryptionKey,
    webauthn: Webauthn,
}

#[derive(Debug, Error)]
pub enum AuthFactorServiceError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket operation failed: {0}")]
    Ticket(#[from] LoginTicketStoreError),
    #[error("secret operation failed: {0}")]
    Secret(#[from] SecretCryptoError),
    #[error("TOTP enrollment operation failed: {0}")]
    Totp(#[from] totp_rs::TotpUrlError),
    #[error("WebAuthn operation failed: {0}")]
    Webauthn(#[from] WebauthnError),
}

impl AuthFactorService {
    pub fn new(
        pool: PgPool,
        redis: Client,
        encryption_key: AuthEncryptionKey,
        rp_id: &str,
        origin: &str,
    ) -> Result<Self, WebauthnError> {
        let origin = url::Url::parse(origin).map_err(|_| WebauthnError::Configuration)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?.build()?;
        Ok(Self {
            pool,
            tickets: LoginTicketStore::new(redis),
            encryption_key,
            webauthn,
        })
    }

    pub async fn available_methods(
        &self,
        user_id: UserId,
    ) -> Result<Vec<FactorMethod>, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        Ok(methods
            .into_iter()
            .filter_map(|method| match method.as_str() {
                "totp" => Some(FactorMethod::Totp),
                "passkey" => Some(FactorMethod::Passkey),
                _ => None,
            })
            .collect())
    }

    pub async fn create_login_ticket(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
    ) -> Result<(String, LoginTicket), AuthFactorServiceError> {
        Ok(self.tickets.create(user_id, methods).await?)
    }

    pub async fn user_id_for_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<Option<UserId>, AuthFactorServiceError> {
        Ok(self
            .tickets
            .find(ticket_id)
            .await?
            .map(|ticket| ticket.user_id))
    }

    pub async fn verify_totp(
        &self,
        user_id: UserId,
        code: &str,
    ) -> Result<bool, AuthFactorServiceError> {
        let Some(encrypted_secret) = repository::find_totp_secret(&self.pool, user_id).await?
        else {
            return Ok(false);
        };
        let mut secret = decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        Ok(valid)
    }

    pub async fn start_totp_enrollment(
        &self,
        ticket_id: &str,
        account_name: &str,
        issuer: &str,
    ) -> Result<Option<TotpEnrollment>, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(None);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
            || !repository::list_factor_methods(&self.pool, ticket.user_id)
                .await?
                .is_empty()
        {
            return Ok(None);
        }
        if self
            .tickets
            .find_json::<PendingTotpSetup>(&Self::totp_setup_key(ticket_id))
            .await?
            .is_some()
        {
            return Ok(None);
        }
        let enrollment = TotpEnrollment::new(account_name, issuer)?;
        let encrypted_secret = super::crypto::encrypt_totp_secret(
            self.encryption_key.as_bytes(),
            enrollment.secret_bytes(),
        )?;
        self.tickets
            .save_json(
                &Self::totp_setup_key(ticket_id),
                &PendingTotpSetup {
                    user_id: ticket.user_id,
                    encrypted_secret,
                },
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(Some(enrollment))
    }

    pub async fn confirm_totp_enrollment(
        &self,
        ticket_id: &str,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        let Some(pending) = self
            .tickets
            .find_json::<PendingTotpSetup>(&Self::totp_setup_key(ticket_id))
            .await?
        else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let mut secret =
            decrypt_totp_secret(self.encryption_key.as_bytes(), &pending.encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            return Ok(TotpConfirmation::InvalidCode);
        }
        let confirmation = persist_then_consume(
            ticket.user_id,
            repository::insert_totp_factor(&self.pool, ticket.user_id, &pending.encrypted_secret),
            self.tickets.take(ticket_id),
        )
        .await?;
        self.tickets
            .delete(&Self::totp_setup_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

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

    pub async fn verify_totp_login(
        &self,
        ticket_id: &str,
        code: &str,
    ) -> Result<TotpConfirmation, AuthFactorServiceError> {
        let Some(ticket) = self.tickets.find(ticket_id).await? else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        if !ticket.is_active_at(time::OffsetDateTime::now_utc())
            || !ticket.supports(FactorMethod::Totp)
        {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        let Some(encrypted_secret) =
            repository::find_totp_secret(&self.pool, ticket.user_id).await?
        else {
            return Ok(TotpConfirmation::InvalidTicket);
        };
        let mut secret = decrypt_totp_secret(self.encryption_key.as_bytes(), &encrypted_secret)?;
        let valid = verify_totp_code_current(&secret, code);
        secret.fill(0);
        if !valid {
            return Ok(TotpConfirmation::InvalidCode);
        }
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(TotpConfirmation::InvalidTicket);
        }
        Ok(TotpConfirmation::Completed(ticket.user_id))
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
        if self.tickets.take(ticket_id).await?.is_none() {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        if result.needs_update()
            && passkey
                .update_credential(&result)
                .is_some_and(|changed| changed)
        {
            repository::update_passkey(&self.pool, result.cred_id(), passkey).await?;
        }
        self.tickets
            .delete(&Self::passkey_authentication_key(ticket_id))
            .await?;
        Ok(PasskeyConfirmation::Completed(ticket.user_id))
    }

    fn totp_setup_key(ticket_id: &str) -> String {
        format!("{TOTP_SETUP_PREFIX}{ticket_id}")
    }

    fn passkey_registration_key(ticket_id: &str) -> String {
        format!("{PASSKEY_REGISTRATION_PREFIX}{ticket_id}")
    }

    fn passkey_authentication_key(ticket_id: &str) -> String {
        format!("{PASSKEY_AUTHENTICATION_PREFIX}{ticket_id}")
    }
}
