//! Authenticated account-management enrollment.
//!
//! This state is deliberately separate from login tickets. A pending enrollment
//! cannot satisfy login policy and is bound to one user, browser session and
//! session epoch until it is confirmed or expires.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::proto::CreationChallengeResponse;

use super::{
    AuthFactorService, AuthFactorServiceError,
    passkey_core::{
        PendingPasskeyRegistration, authenticator_attachment, build_core, passkey_from_credential,
        passkey_registration_extensions, user_verification_policy,
    },
};
use crate::{
    auth_factors::{
        crypto::{SecretCryptoError, decrypt_totp_secret_with_ring, encrypt_totp_secret_with_ring},
        domain::{FactorMethod, LoginTicket},
        repository,
        totp::{TotpEnrollment, verify_totp_code_now_timestep},
    },
    users::domain::UserId,
};
use webauthn_rs_core::proto::{AttestationConveyancePreference, COSEAlgorithm};

const SESSION_ENROLLMENT_PREFIX: &str = "chenxing:auth:session-enrollment:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionFactorSummary {
    pub totp_enabled: bool,
    pub passkey_count: i64,
    pub available_methods: Vec<FactorMethod>,
}

#[derive(Debug)]
pub enum EnrollmentStart<T> {
    Started(T),
    AlreadyPending,
    AlreadyExists,
}

#[derive(Debug)]
pub enum EnrollmentFinish {
    Completed,
    InvalidEnrollment,
    InvalidCredential,
    KeyUnavailable,
    AlreadyExists,
    AuthenticationChanged,
}

#[derive(Debug)]
pub struct SessionTotpStart {
    pub enrollment_id: String,
    pub enrollment: TotpEnrollment,
}

#[derive(Debug)]
pub struct SessionPasskeyStart {
    pub enrollment_id: String,
    pub options: CreationChallengeResponse,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingSessionEnrollment<P> {
    binding: PendingSessionBinding,
    method: FactorMethod,
    enrollment_id: String,
    expires_at: OffsetDateTime,
    payload: P,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingSessionBinding {
    user_id: String,
    session_id: String,
    session_epoch: String,
}

impl PendingSessionBinding {
    fn new(user_id: UserId, session_id: i64, session_epoch: i64) -> Self {
        Self {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            session_epoch: session_epoch.to_string(),
        }
    }
}

impl<P> fmt::Debug for PendingSessionEnrollment<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSessionEnrollment")
            .field("binding", &self.binding)
            .field("method", &self.method)
            .field("enrollment_id", &self.enrollment_id)
            .field("expires_at", &self.expires_at)
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingTotpPayload {
    encrypted_secret: Vec<u8>,
}

impl AuthFactorService {
    pub async fn session_factor_summary(
        &self,
        user_id: UserId,
    ) -> Result<SessionFactorSummary, AuthFactorServiceError> {
        let methods = repository::list_factor_methods(&self.pool, user_id).await?;
        let passkey_count = repository::count_passkeys(&self.pool, user_id).await?;
        let passkey_enabled = self.settings.passkey().await?.enabled;
        Ok(SessionFactorSummary {
            totp_enabled: methods.iter().any(|method| method == "totp"),
            passkey_count,
            available_methods: crate::auth_factors::domain::effective_factor_methods(
                methods,
                passkey_enabled,
            ),
        })
    }

    pub async fn start_session_totp_enrollment(
        &self,
        user_id: UserId,
        session_id: i64,
        expected_session_epoch: i64,
        account_name: &str,
        issuer: &str,
    ) -> Result<EnrollmentStart<SessionTotpStart>, AuthFactorServiceError> {
        if repository::find_totp_secret(&self.pool, user_id)
            .await?
            .is_some()
        {
            return Ok(EnrollmentStart::AlreadyExists);
        }
        let session_epoch = self.current_epoch(user_id).await?;
        if session_epoch != expected_session_epoch {
            return Err(AuthFactorServiceError::AuthenticationEpochChanged);
        }
        let enrollment = TotpEnrollment::new(account_name, issuer)?;
        let pending = PendingSessionEnrollment {
            binding: PendingSessionBinding::new(user_id, session_id, session_epoch),
            method: FactorMethod::Totp,
            enrollment_id: Uuid::new_v4().to_string(),
            expires_at: self.clock.now() + LoginTicket::TTL,
            payload: PendingTotpPayload {
                encrypted_secret: encrypt_totp_secret_with_ring(
                    &self.encryption_keys,
                    enrollment.secret_bytes(),
                )?,
            },
        };
        if !self.reserve_session_enrollment(user_id, &pending).await? {
            return Ok(EnrollmentStart::AlreadyPending);
        }
        Ok(EnrollmentStart::Started(SessionTotpStart {
            enrollment_id: pending.enrollment_id,
            enrollment,
        }))
    }

    pub async fn confirm_session_totp_enrollment(
        &self,
        user_id: UserId,
        session_id: i64,
        enrollment_id: &str,
        code: &str,
    ) -> Result<EnrollmentFinish, AuthFactorServiceError> {
        let session_epoch = self.current_epoch(user_id).await?;
        let key = self.session_enrollment_key(user_id, FactorMethod::Totp);
        let Some(pending) = self
            .tickets
            .find_json::<PendingSessionEnrollment<PendingTotpPayload>>(&key)
            .await?
        else {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        };
        if !pending.matches(
            user_id,
            session_id,
            session_epoch,
            FactorMethod::Totp,
            enrollment_id,
        ) || self.clock.now() >= pending.expires_at
        {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        }
        let decrypted = match decrypt_totp_secret_with_ring(
            &self.encryption_keys,
            &pending.payload.encrypted_secret,
        ) {
            Ok(secret) => secret,
            Err(SecretCryptoError::UnknownKeyId) => {
                return Ok(
                    if self
                        .take_session_enrollment::<PendingTotpPayload>(
                            &key,
                            user_id,
                            session_id,
                            session_epoch,
                            FactorMethod::Totp,
                            enrollment_id,
                        )
                        .await?
                        .is_some()
                    {
                        EnrollmentFinish::KeyUnavailable
                    } else {
                        EnrollmentFinish::InvalidEnrollment
                    },
                );
            }
            Err(error) => return Err(error.into()),
        };
        let Some(timestep) =
            verify_totp_code_now_timestep(&decrypted.plaintext, code, self.clock.now())
        else {
            return Ok(EnrollmentFinish::InvalidCredential);
        };
        if !self.tickets.claim_totp_timestep(user_id, timestep).await? {
            return Ok(EnrollmentFinish::InvalidCredential);
        }
        let Some(consumed) = self
            .take_session_enrollment::<PendingTotpPayload>(
                &key,
                user_id,
                session_id,
                session_epoch,
                FactorMethod::Totp,
                enrollment_id,
            )
            .await?
        else {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        };
        match repository::insert_authenticated_totp_factor(
            &self.pool,
            user_id,
            session_epoch,
            &consumed.payload.encrypted_secret,
        )
        .await
        {
            Ok(repository::AuthenticatedTotpPersistenceResult::Stored) => {
                Ok(EnrollmentFinish::Completed)
            }
            Ok(repository::AuthenticatedTotpPersistenceResult::AlreadyExists) => {
                Ok(EnrollmentFinish::AlreadyExists)
            }
            Ok(repository::AuthenticatedTotpPersistenceResult::AuthenticationChanged) => {
                Ok(EnrollmentFinish::AuthenticationChanged)
            }
            Err(error) => {
                self.restore_session_enrollment(&key, &consumed).await?;
                Err(error.into())
            }
        }
    }

    pub async fn start_session_passkey_registration(
        &self,
        user_id: UserId,
        session_id: i64,
        user_name: &str,
        display_name: &str,
    ) -> Result<EnrollmentStart<SessionPasskeyStart>, AuthFactorServiceError> {
        let (settings, issuer_generation) = self.enabled_passkey_settings_with_generation().await?;
        let session_epoch = self.current_epoch(user_id).await?;
        let existing = repository::list_passkeys(&self.pool, user_id).await?;
        let exclude = Some(
            existing
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect(),
        );
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_register_builder(
                Uuid::from_u128(user_id as u128).as_bytes(),
                user_name,
                display_name,
            )?
            .attestation(AttestationConveyancePreference::None)
            .credential_algorithms(COSEAlgorithm::secure_algs())
            .require_resident_key(false)
            .authenticator_attachment(authenticator_attachment(&settings))
            .user_verification_policy(user_verification_policy(&settings))
            .reject_synchronised_authenticators(false)
            .exclude_credentials(exclude)
            .hints(None)
            .extensions(Some(passkey_registration_extensions(&settings)));
        let (options, state) = core.generate_challenge_register(builder)?;
        let pending = PendingSessionEnrollment {
            binding: PendingSessionBinding::new(user_id, session_id, session_epoch),
            method: FactorMethod::Passkey,
            enrollment_id: Uuid::new_v4().to_string(),
            expires_at: self.clock.now() + LoginTicket::TTL,
            payload: PendingPasskeyRegistration {
                user_id,
                state,
                settings,
                issuer_generation: Some(issuer_generation),
            },
        };
        if !self.reserve_session_enrollment(user_id, &pending).await? {
            return Ok(EnrollmentStart::AlreadyPending);
        }
        Ok(EnrollmentStart::Started(SessionPasskeyStart {
            enrollment_id: pending.enrollment_id,
            options,
        }))
    }

    pub async fn finish_session_passkey_registration(
        &self,
        user_id: UserId,
        session_id: i64,
        enrollment_id: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<EnrollmentFinish, AuthFactorServiceError> {
        let (_, current_issuer_generation) =
            self.enabled_passkey_settings_with_generation().await?;
        let session_epoch = self.current_epoch(user_id).await?;
        let key = self.session_enrollment_key(user_id, FactorMethod::Passkey);
        let Some(pending) = self
            .tickets
            .find_json::<PendingSessionEnrollment<PendingPasskeyRegistration>>(&key)
            .await?
        else {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        };
        if !pending.matches(
            user_id,
            session_id,
            session_epoch,
            FactorMethod::Passkey,
            enrollment_id,
        ) || self.clock.now() >= pending.expires_at
        {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        }
        if pending.payload.issuer_generation != Some(current_issuer_generation) {
            let _ = self
                .take_session_enrollment::<PendingPasskeyRegistration>(
                    &key,
                    user_id,
                    session_id,
                    session_epoch,
                    FactorMethod::Passkey,
                    enrollment_id,
                )
                .await?;
            return Ok(EnrollmentFinish::InvalidEnrollment);
        }
        let core = build_core(&pending.payload.settings)?;
        let credential = match core.register_credential(credential, &pending.payload.state, None) {
            Ok(credential) => credential,
            Err(_) => return Ok(EnrollmentFinish::InvalidCredential),
        };
        let passkey = passkey_from_credential(credential)?;
        let Some(consumed) = self
            .take_session_enrollment::<PendingPasskeyRegistration>(
                &key,
                user_id,
                session_id,
                session_epoch,
                FactorMethod::Passkey,
                enrollment_id,
            )
            .await?
        else {
            return Ok(EnrollmentFinish::InvalidEnrollment);
        };
        match repository::insert_authenticated_passkey_with_issuer_generation(
            &self.pool,
            user_id,
            session_epoch,
            passkey.cred_id(),
            &passkey,
            current_issuer_generation,
        )
        .await
        {
            Ok(repository::AuthenticatedPasskeyPersistenceResult::Stored) => {
                Ok(EnrollmentFinish::Completed)
            }
            Ok(repository::AuthenticatedPasskeyPersistenceResult::Conflict) => {
                Ok(EnrollmentFinish::AlreadyExists)
            }
            Ok(repository::AuthenticatedPasskeyPersistenceResult::IssuerChanged) => {
                Ok(EnrollmentFinish::InvalidEnrollment)
            }
            Ok(repository::AuthenticatedPasskeyPersistenceResult::AuthenticationChanged) => {
                Ok(EnrollmentFinish::AuthenticationChanged)
            }
            Err(error) => {
                self.restore_session_enrollment(&key, &consumed).await?;
                Err(error.into())
            }
        }
    }

    async fn current_epoch(&self, user_id: UserId) -> Result<i64, AuthFactorServiceError> {
        repository::find_session_epoch(&self.pool, user_id)
            .await?
            .ok_or(AuthFactorServiceError::UserNotFound)
    }

    async fn reserve_session_enrollment<P: Serialize>(
        &self,
        user_id: UserId,
        pending: &PendingSessionEnrollment<P>,
    ) -> Result<bool, AuthFactorServiceError> {
        Ok(self
            .tickets
            .save_json_if_absent(
                &self.session_enrollment_key(user_id, pending.method),
                pending,
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?)
    }

    async fn take_session_enrollment<P: DeserializeOwned>(
        &self,
        key: &str,
        user_id: UserId,
        session_id: i64,
        session_epoch: i64,
        method: FactorMethod,
        enrollment_id: &str,
    ) -> Result<Option<PendingSessionEnrollment<P>>, AuthFactorServiceError> {
        Ok(self
            .tickets
            .take_session_enrollment_if_owner(
                key,
                user_id,
                session_id,
                session_epoch,
                method,
                enrollment_id,
            )
            .await?)
    }

    async fn restore_session_enrollment<P: Serialize>(
        &self,
        key: &str,
        pending: &PendingSessionEnrollment<P>,
    ) -> Result<(), AuthFactorServiceError> {
        let ttl = (pending.expires_at - self.clock.now()).whole_seconds();
        if ttl > 0 {
            let _ = self
                .tickets
                .save_json_if_absent(key, pending, ttl as u64)
                .await?;
        }
        Ok(())
    }

    fn session_enrollment_key(&self, user_id: UserId, method: FactorMethod) -> String {
        let method = match method {
            FactorMethod::Totp => "totp",
            FactorMethod::Passkey => "passkey",
        };
        self.tickets
            .namespaced(&format!("{SESSION_ENROLLMENT_PREFIX}{user_id}:{method}"))
    }
}

impl<P> PendingSessionEnrollment<P> {
    fn matches(
        &self,
        user_id: UserId,
        session_id: i64,
        session_epoch: i64,
        method: FactorMethod,
        enrollment_id: &str,
    ) -> bool {
        self.binding.user_id == user_id.to_string()
            && self.binding.session_id == session_id.to_string()
            && self.binding.session_epoch == session_epoch.to_string()
            && self.method == method
            && self.enrollment_id == enrollment_id
    }
}
