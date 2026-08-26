//! 用户安全事件的分级体系（Issue #308 / #467）。
//!
//! 生产代码只能发出 [`AuditAction`]。落库字符串、历史读取和列表/详情展示仍走
//! [`classify`]：已知值与枚举分类一致，未知历史值兼容回退为 `account/info`。

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventCategory {
    Auth,
    Session,
    Authorization,
    Account,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventSeverity {
    Info,
    Notice,
    Warning,
    Critical,
}

type Classification = (SecurityEventCategory, SecurityEventSeverity);

const UNKNOWN_CLASSIFICATION: Classification =
    (SecurityEventCategory::Account, SecurityEventSeverity::Info);

macro_rules! audit_actions {
    ($($variant:ident => $name:literal => ($category:ident, $severity:ident)),+ $(,)?) => {
        /// 生产审计 action。新增变体必须同时声明落库字符串和分类。
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum AuditAction {
            $($variant),+
        }

        impl AuditAction {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub const fn classification(self) -> Classification {
                match self {
                    $(Self::$variant => (
                        SecurityEventCategory::$category,
                        SecurityEventSeverity::$severity,
                    )),+
                }
            }
        }
    };
}

audit_actions! {
    Login => "login" => (Auth, Notice),
    LoginFailure => "login_failure" => (Auth, Warning),
    LoginFailed => "login_failed" => (Auth, Warning),
    LoginRateLimited => "login_rate_limited" => (Auth, Warning),
    MfaFailure => "mfa_failure" => (Auth, Warning),
    RateLimitTriggered => "rate_limit_triggered" => (Auth, Warning),
    PasskeyRecoveryRequired => "passkey_recovery_required" => (Auth, Warning),
    AuthFactorKeyUnavailable => "auth_factor_key_unavailable" => (Auth, Warning),
    OauthProviderCreate => "oauth_provider_create" => (Auth, Critical),
    OauthProviderUpdate => "oauth_provider_update" => (Auth, Critical),
    OauthProviderActive => "oauth_provider_active" => (Auth, Critical),
    OauthProviderDisabled => "oauth_provider_disabled" => (Auth, Warning),
    ExternalIdentityLink => "external_identity_link" => (Account, Notice),
    ExternalIdentityUnlink => "external_identity_unlink" => (Account, Critical),
    PasskeySettingUpdate => "passkey_setting_update" => (Auth, Critical),

    SessionRevoke => "session_revoke" => (Session, Warning),

    OauthConsent => "oauth_consent" => (Authorization, Notice),
    AuthorizationCodeIssue => "authorization_code_issue" => (Authorization, Notice),
    TokenExchange => "token_exchange" => (Authorization, Notice),
    TokenRefresh => "token_refresh" => (Authorization, Notice),
    ClientCreate => "client_create" => (Authorization, Notice),
    ConsentRevoke => "consent_revoke" => (Authorization, Warning),
    OauthConsentRevoke => "oauth_consent_revoke" => (Authorization, Warning),
    AuthorizationRequestRebound => "authorization_request_rebound" => (Authorization, Warning),
    TokenExchangeFailure => "token_exchange_failure" => (Authorization, Warning),
    TokenRefreshFailure => "token_refresh_failure" => (Authorization, Warning),
    TokenRevoke => "token_revoke" => (Authorization, Warning),
    ClientDisabled => "client_disabled" => (Authorization, Warning),
    ClientSecretRotateConflict => "client_secret_rotate_conflict" => (Authorization, Warning),
    AuthorizationDenied => "authorization_denied" => (Authorization, Info),
    ClientUpdate => "client_update" => (Authorization, Critical),
    ClientActive => "client_active" => (Authorization, Critical),
    ClientSecretRotate => "client_secret_rotate" => (Authorization, Critical),
    SigningKeyRotate => "signing_key_rotate" => (Authorization, Critical),
    SigningKeyRevoke => "signing_key_revoke" => (Authorization, Critical),
    IssuerConfigure => "issuer_configure" => (Authorization, Critical),
    IssuerUpdate => "issuer_update" => (Authorization, Critical),

    UserAvatarUpdate => "user_avatar_update" => (Account, Info),
    UserAvatarRemove => "user_avatar_remove" => (Account, Info),
    UserProfileUpdate => "user_profile_update" => (Account, Info),
    UserUsernameChange => "user_username_change" => (Account, Critical),
    UserEmailChange => "user_email_change" => (Account, Critical),
    UserRegister => "user_register" => (Account, Notice),
    RegistrationEmailUpdate => "registration_email_update" => (Account, Notice),
    PlanCreate => "plan_create" => (Account, Notice),
    PlanUpdate => "plan_update" => (Account, Notice),
    PlanArchive => "plan_archive" => (Account, Notice),
    PlanRestore => "plan_restore" => (Account, Notice),
    UserPlanAssign => "user_plan_assign" => (Account, Notice),
    PlanPurchase => "plan_purchase" => (Account, Notice),
    WalletCredit => "wallet_credit" => (Account, Critical),
    AdminAuthorizationDenied => "admin_authorization_denied" => (Account, Warning),
    AdminOwnerGuardDenied => "admin_owner_guard_denied" => (Account, Warning),
    PasswordChange => "password_change" => (Account, Critical),
    UserTotpFactorReset => "user_totp_factor_reset" => (Account, Critical),
    UserPasskeyFactorReset => "user_passkey_factor_reset" => (Account, Critical),
    UserTotpFactorEnroll => "user_totp_factor_enroll" => (Account, Notice),
    UserPasskeyFactorEnroll => "user_passkey_factor_enroll" => (Account, Notice),
    UserTotpFactorRemove => "user_totp_factor_remove" => (Account, Critical),
    UserPasskeyFactorRemove => "user_passkey_factor_remove" => (Account, Critical),
    OwnerBootstrap => "owner_bootstrap" => (Account, Critical),
    UserCreate => "user_create" => (Account, Critical),
    UserActive => "user_active" => (Account, Critical),
    UserDisabled => "user_disabled" => (Account, Critical),
    UserRoleUpdate => "user_role_update" => (Account, Critical),
    EmailPolicyUpdate => "email_policy_update" => (Account, Critical),
    RegistrationSettingUpdate => "registration_setting_update" => (Account, Critical),
    InvitationCodeCreate => "invitation_code_create" => (Account, Critical),
    InvitationCodeDisable => "invitation_code_disable" => (Account, Critical),
    SmtpSettingUpdate => "smtp_setting_update" => (Account, Critical),
    SecurityLimitsUpdate => "security_limits_update" => (Account, Critical),
    SessionLifetimeUpdate => "session_lifetime_update" => (Session, Critical),
}

/// 列表与详情共用的 action 分类入口。未知历史值保持可见并沿用旧回退。
pub fn classify(action: &str) -> Classification {
    AuditAction::parse(action)
        .map(AuditAction::classification)
        .unwrap_or(UNKNOWN_CLASSIFICATION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_production_action_is_explicitly_classified() {
        for action in AuditAction::ALL {
            assert_eq!(classify(action.as_str()), action.classification());
            assert_eq!(AuditAction::parse(action.as_str()), Some(*action));
        }
    }

    #[test]
    fn high_risk_actions_never_downgrade_to_info() {
        for action in [
            AuditAction::ClientSecretRotate,
            AuditAction::SigningKeyRevoke,
            AuditAction::UserRoleUpdate,
            AuditAction::TokenRefreshFailure,
        ] {
            assert_ne!(
                action.classification().1,
                SecurityEventSeverity::Info,
                "{} must not be info",
                action.as_str()
            );
        }
    }

    #[test]
    fn unknown_historical_actions_keep_account_info_fallback() {
        for action in ["some_future_action", "", "test"] {
            assert_eq!(AuditAction::parse(action), None);
            assert_eq!(classify(action), UNKNOWN_CLASSIFICATION);
        }
    }
}
