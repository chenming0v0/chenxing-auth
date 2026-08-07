//! Passkey 的 WebAuthn 协议翻译层：把运行时 `PasskeySetting` 映射为 `WebauthnCore`
//! 及其策略参数，并在存储用的 `Passkey` 与协议用的 `Credential` 之间转换。
//! 这里不涉及 ticket、限流或数据库，只做纯粹的协议与配置换算。

use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};
use webauthn_rs::prelude::Passkey;
use webauthn_rs_core::{
    WebauthnCore,
    proto::{
        AuthenticationState, AuthenticatorAttachment, CredProtect, Credential,
        CredentialProtectionPolicy, RegistrationState, RequestRegistrationExtensions,
        UserVerificationPolicy,
    },
};

use super::AuthFactorServiceError;

const AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(300);

/// 挂起的注册状态。`settings` 是 challenge 签发时的配置快照，确保 finish 阶段
/// 使用与 start 相同的 RP 和 origin，即使中途管理员改了设置。
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PendingPasskeyRegistration {
    pub(super) user_id: i64,
    pub(super) state: RegistrationState,
    pub(super) settings: crate::settings::PasskeySetting,
}

impl fmt::Debug for PendingPasskeyRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPasskeyRegistration")
            .field("user_id", &self.user_id)
            .field("state", &"<redacted>")
            .field("settings", &self.settings)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PendingPasskeyAuthentication {
    pub(super) user_id: i64,
    pub(super) state: AuthenticationState,
    pub(super) settings: crate::settings::PasskeySetting,
}

impl fmt::Debug for PendingPasskeyAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPasskeyAuthentication")
            .field("user_id", &self.user_id)
            .field("state", &"<redacted>")
            .field("settings", &self.settings)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PasskeyEnvelope {
    cred: Credential,
}

impl fmt::Debug for PasskeyEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyEnvelope")
            .field("cred", &"<redacted>")
            .finish()
    }
}

pub(super) fn build_core(
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

pub(super) fn user_verification_policy(
    settings: &crate::settings::PasskeySetting,
) -> UserVerificationPolicy {
    match settings.user_verification {
        crate::settings::PasskeyUserVerification::Preferred => UserVerificationPolicy::Preferred,
        crate::settings::PasskeyUserVerification::Required => UserVerificationPolicy::Required,
        crate::settings::PasskeyUserVerification::Discouraged => {
            UserVerificationPolicy::Discouraged_DO_NOT_USE
        }
    }
}

pub(super) fn authenticator_attachment(
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

pub(super) fn passkey_registration_extensions() -> RequestRegistrationExtensions {
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

pub(super) fn core_credential(passkey: &Passkey) -> Result<Credential, AuthFactorServiceError> {
    Ok(serde_json::from_value::<PasskeyEnvelope>(serde_json::to_value(passkey)?)?.cred)
}

pub(super) fn passkey_from_credential(
    credential: Credential,
) -> Result<Passkey, AuthFactorServiceError> {
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
