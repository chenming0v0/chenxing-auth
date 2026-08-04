use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};
use webauthn_rs_core::{
    WebauthnCore,
    proto::{
        AttestationConveyancePreference, AuthenticationState, AuthenticatorAttachment,
        COSEAlgorithm, CreationChallengeResponse, CredProtect, Credential,
        CredentialProtectionPolicy, RegistrationState, RequestChallengeResponse,
        RequestRegistrationExtensions, UserVerificationPolicy,
    },
};

use super::{AuthFactorService, AuthFactorServiceError, PasskeyConfirmation};
use crate::auth_factors::{
    domain::{FactorMethod, LoginTicket},
    persistence::consume_then_persist,
    repository,
};

const PASSKEY_REGISTRATION_PREFIX: &str = "chenxing:auth:passkey-registration:";
const PASSKEY_AUTHENTICATION_PREFIX: &str = "chenxing:auth:passkey-authentication:";
const AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyRegistration {
    user_id: i64,
    state: RegistrationState,
    settings: crate::settings::PasskeySetting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingPasskeyAuthentication {
    user_id: i64,
    state: AuthenticationState,
    settings: crate::settings::PasskeySetting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyEnvelope {
    cred: Credential,
}

impl AuthFactorService {
    async fn enabled_passkey_settings(
        &self,
    ) -> Result<crate::settings::PasskeySetting, AuthFactorServiceError> {
        let settings = self.settings.passkey().await?;
        if settings.enabled {
            Ok(settings)
        } else {
            Err(AuthFactorServiceError::PasskeyDisabled)
        }
    }

    pub async fn start_passkey_registration(
        &self,
        ticket_id: &str,
        user_name: &str,
        display_name: &str,
    ) -> Result<Option<CreationChallengeResponse>, AuthFactorServiceError> {
        let settings = self.enabled_passkey_settings().await?;
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
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_register_builder(
                Uuid::from_u128(ticket.user_id as u128).as_bytes(),
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
            .extensions(Some(passkey_registration_extensions()));
        let (challenge, state) = core.generate_challenge_register(builder)?;
        self.tickets
            .save_json(
                &Self::passkey_registration_key(ticket_id),
                &PendingPasskeyRegistration {
                    user_id: ticket.user_id,
                    state,
                    settings,
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
        self.enabled_passkey_settings().await?;
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
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let core = build_core(&pending.settings)?;
        let credential = match core.register_credential(credential, &pending.state, None) {
            Ok(credential) => credential,
            Err(_) => return Ok(PasskeyConfirmation::InvalidCredential),
        };
        let passkey = passkey_from_credential(credential)?;
        let confirmation = match consume_then_persist(
            PasskeyConfirmation::Completed(ticket.user_id),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take(ticket_id),
            async {
                match repository::insert_passkey_if_empty(
                    &self.pool,
                    ticket.user_id,
                    passkey.cred_id(),
                    &passkey,
                )
                .await?
                {
                    repository::PasskeyPersistenceResult::Stored => Ok(()),
                    repository::PasskeyPersistenceResult::Conflict => {
                        Err(AuthFactorServiceError::FirstFactorAlreadyExists)
                    }
                }
            },
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await
        {
            Ok(confirmation) => confirmation,
            Err(AuthFactorServiceError::FirstFactorAlreadyExists) => {
                let _ = self.tickets.take(ticket_id).await?;
                self.tickets
                    .delete(&Self::passkey_registration_key(ticket_id))
                    .await?;
                return Ok(PasskeyConfirmation::InvalidTicket);
            }
            Err(error) => return Err(error),
        };
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
        self.tickets
            .delete(&Self::passkey_registration_key(ticket_id))
            .await?;
        Ok(confirmation)
    }

    pub async fn start_passkey_authentication(
        &self,
        ticket_id: &str,
    ) -> Result<Option<RequestChallengeResponse>, AuthFactorServiceError> {
        let settings = self.enabled_passkey_settings().await?;
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
        let credentials = passkeys
            .iter()
            .map(core_credential)
            .collect::<Result<Vec<_>, _>>()?;
        let core = build_core(&settings)?;
        let builder = core
            .new_challenge_authenticate_builder(
                credentials,
                Some(user_verification_policy(&settings)),
            )?
            .extensions(None)
            .allow_backup_eligible_upgrade(true)
            .hints(None);
        let (challenge, state) = core.generate_challenge_authenticate(builder)?;
        self.tickets
            .save_json(
                &Self::passkey_authentication_key(ticket_id),
                &PendingPasskeyAuthentication {
                    user_id: ticket.user_id,
                    state,
                    settings,
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
        self.enabled_passkey_settings().await?;
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
        if pending.user_id != ticket.user_id {
            return Ok(PasskeyConfirmation::InvalidTicket);
        }
        let core = build_core(&pending.settings)?;
        let result = match core.authenticate_credential(credential, &pending.state) {
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
        let confirmation = consume_then_persist(
            PasskeyConfirmation::Completed(ticket.user_id),
            PasskeyConfirmation::InvalidTicket,
            self.tickets.take(ticket_id),
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
            |ticket| self.tickets.restore(ticket_id, ticket),
        )
        .await?;
        if matches!(confirmation, PasskeyConfirmation::InvalidTicket) {
            return Ok(confirmation);
        }
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

fn build_core(
    settings: &crate::settings::PasskeySetting,
) -> Result<WebauthnCore, AuthFactorServiceError> {
    let settings = settings
        .clone()
        .validate()
        .map_err(|_| webauthn_rs::prelude::WebauthnError::Configuration)?;
    let allowed_origins = settings
        .allowed_origins
        .iter()
        .map(|origin| {
            url::Url::parse(origin).map_err(|_| webauthn_rs::prelude::WebauthnError::Configuration)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WebauthnCore::new_unsafe_experts_only(
        &settings.rp_name,
        &settings.rp_id,
        allowed_origins,
        AUTHENTICATOR_TIMEOUT,
        Some(false),
        Some(false),
    ))
}

fn user_verification_policy(settings: &crate::settings::PasskeySetting) -> UserVerificationPolicy {
    match settings.user_verification {
        crate::settings::PasskeyUserVerification::Preferred => UserVerificationPolicy::Preferred,
        crate::settings::PasskeyUserVerification::Required => UserVerificationPolicy::Required,
        crate::settings::PasskeyUserVerification::Discouraged => {
            UserVerificationPolicy::Discouraged_DO_NOT_USE
        }
    }
}

fn authenticator_attachment(
    settings: &crate::settings::PasskeySetting,
) -> Option<AuthenticatorAttachment> {
    match settings.authenticator_attachment {
        crate::settings::PasskeyAuthenticatorAttachment::Any => None,
        crate::settings::PasskeyAuthenticatorAttachment::Platform => {
            Some(AuthenticatorAttachment::Platform)
        }
        crate::settings::PasskeyAuthenticatorAttachment::CrossPlatform => {
            Some(AuthenticatorAttachment::CrossPlatform)
        }
    }
}

fn passkey_registration_extensions() -> RequestRegistrationExtensions {
    RequestRegistrationExtensions {
        cred_protect: Some(CredProtect {
            credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
            enforce_credential_protection_policy: Some(false),
        }),
        uvm: Some(true),
        cred_props: Some(true),
        min_pin_length: None,
        hmac_create_secret: None,
    }
}

fn core_credential(passkey: &Passkey) -> Result<Credential, AuthFactorServiceError> {
    Ok(serde_json::from_value::<PasskeyEnvelope>(serde_json::to_value(passkey)?)?.cred)
}

fn passkey_from_credential(credential: Credential) -> Result<Passkey, AuthFactorServiceError> {
    Ok(serde_json::from_value(serde_json::to_value(
        PasskeyEnvelope { cred: credential },
    )?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{
        PasskeyAuthenticatorAttachment, PasskeySetting, PasskeyUserVerification,
    };

    fn settings(
        user_verification: PasskeyUserVerification,
        authenticator_attachment: PasskeyAuthenticatorAttachment,
    ) -> PasskeySetting {
        PasskeySetting {
            enabled: true,
            rp_name: "Configured RP".to_owned(),
            rp_id: "example.com".to_owned(),
            user_verification,
            authenticator_attachment,
            allow_insecure_origin: false,
            allowed_origins: vec!["https://login.example.com".to_owned()],
        }
    }

    #[test]
    fn core_challenge_uses_runtime_rp_uv_attachment_and_origins() {
        let settings = settings(
            PasskeyUserVerification::Preferred,
            PasskeyAuthenticatorAttachment::Platform,
        );
        let core = build_core(&settings).expect("valid passkey core");
        assert_eq!(
            core.get_allowed_origins(),
            &[url::Url::parse("https://login.example.com").expect("origin")]
        );

        let builder = core
            .new_challenge_register_builder(b"user", "user", "User")
            .expect("register builder")
            .authenticator_attachment(authenticator_attachment(&settings))
            .user_verification_policy(user_verification_policy(&settings));
        let (challenge, state) = core
            .generate_challenge_register(builder)
            .expect("register challenge");
        let json = serde_json::to_value(challenge).expect("challenge JSON");
        assert_eq!(json["publicKey"]["rp"]["name"], "Configured RP");
        assert_eq!(json["publicKey"]["rp"]["id"], "example.com");
        assert_eq!(
            json["publicKey"]["authenticatorSelection"]["userVerification"],
            "preferred"
        );
        assert_eq!(
            json["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
            "platform"
        );

        let pending = PendingPasskeyRegistration {
            user_id: 7,
            state,
            settings,
        };
        let pending_json = serde_json::to_value(pending).expect("pending JSON");
        assert_eq!(pending_json["settings"]["rp_name"], "Configured RP");
        assert_eq!(
            pending_json["settings"]["allowed_origins"],
            serde_json::json!(["https://login.example.com"])
        );
    }

    #[test]
    fn core_authentication_challenge_uses_runtime_user_verification() {
        let settings = settings(
            PasskeyUserVerification::Discouraged,
            PasskeyAuthenticatorAttachment::CrossPlatform,
        );
        let core = build_core(&settings).expect("valid passkey core");
        let credential: Credential = serde_json::from_value(serde_json::json!({
            "cred_id": "AQ",
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": "BA",
                        "y": "BQ"
                    }
                }
            },
            "counter": 0,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "preferred",
            "extensions": {},
            "attestation": {"data": "None", "metadata": "None"},
            "attestation_format": "none"
        }))
        .expect("credential");
        let passkey = passkey_from_credential(credential.clone()).expect("passkey envelope");
        assert_eq!(
            serde_json::to_value(core_credential(&passkey).expect("core credential"))
                .expect("credential JSON"),
            serde_json::to_value(&credential).expect("credential JSON")
        );
        let builder = core
            .new_challenge_authenticate_builder(
                vec![credential],
                Some(user_verification_policy(&settings)),
            )
            .expect("authentication builder");
        let (challenge, _) = core
            .generate_challenge_authenticate(builder)
            .expect("authentication challenge");
        let json = serde_json::to_value(challenge).expect("challenge JSON");
        assert_eq!(json["publicKey"]["rpId"], "example.com");
        assert_eq!(json["publicKey"]["userVerification"], "discouraged");
    }
}
