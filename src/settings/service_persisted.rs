use super::{SettingsService, SettingsServiceError};
use crate::audit::{AuditEvent, AuditService};
use crate::settings::{
    SecurityLimitsSetting,
    domain::{EmailPolicySetting, PasskeySetting, RegistrationSetting},
    persisted::{
        PersistedDecode, PersistedLoadError, PersistedSetting, SettingInspection, decode_persisted,
    },
    repository,
};

impl SettingsService {
    pub async fn passkey(&self) -> Result<PasskeySetting, SettingsServiceError> {
        Ok(self.passkey_with_issuer_binding().await?.0)
    }

    pub async fn passkey_with_issuer_binding(
        &self,
    ) -> Result<(PasskeySetting, Option<i64>), SettingsServiceError> {
        let snapshot = self
            .issuer_runtime
            .as_ref()
            .and_then(|runtime| runtime.current());
        let runtime_default = snapshot
            .as_ref()
            .map(|value| {
                PasskeySetting::default()
                    .with_runtime_defaults(value.webauthn_rp_id(), value.webauthn_origin())
            })
            .unwrap_or_else(|| self.default_passkey.clone());
        let setting = self
            .decode_stored::<PasskeySetting>()
            .await?
            .require(
                runtime_default.clone(),
                |value| apply_passkey_runtime_defaults(value, &runtime_default),
                PasskeySetting::validate,
            )
            .map_err(Self::persist_error::<PasskeySetting>)?;
        Ok((setting, snapshot.map(|value| value.generation())))
    }

    pub async fn inspect_passkey(
        &self,
    ) -> Result<SettingInspection<PasskeySetting>, SettingsServiceError> {
        let runtime_default = self.passkey_runtime_default();
        Ok(self.decode_stored::<PasskeySetting>().await?.inspect(
            runtime_default.clone(),
            |value| apply_passkey_runtime_defaults(value, &runtime_default),
            PasskeySetting::validate,
        ))
    }

    pub async fn set_passkey(
        &self,
        value: PasskeySetting,
    ) -> Result<PasskeySetting, SettingsServiceError> {
        let value = value.validate()?;
        let mut transaction = self.pool.begin().await?;
        repository::lock_passkey_policy(&mut transaction).await?;
        repository::set_passkey(&mut *transaction, &value).await?;
        transaction.commit().await?;
        Ok(value)
    }

    pub async fn set_passkey_audited<F>(
        &self,
        value: PasskeySetting,
        audit: &AuditService,
        audit_event: F,
    ) -> Result<PasskeySetting, SettingsServiceError>
    where
        F: FnOnce(&PasskeySetting) -> AuditEvent,
    {
        let value = value.validate()?;
        let mut transaction = self.pool.begin().await?;
        repository::lock_passkey_policy(&mut transaction).await?;
        repository::set_passkey(&mut *transaction, &value).await?;
        audit
            .record_in_transaction(&mut transaction, audit_event(&value))
            .await?;
        transaction.commit().await?;
        Ok(value)
    }

    pub async fn email_policy(&self) -> Result<EmailPolicySetting, SettingsServiceError> {
        self.decode_stored::<EmailPolicySetting>()
            .await?
            .require(
                EmailPolicySetting::default(),
                |value| value,
                EmailPolicySetting::validate,
            )
            .map_err(Self::persist_error::<EmailPolicySetting>)
    }

    pub async fn inspect_email_policy(
        &self,
    ) -> Result<SettingInspection<EmailPolicySetting>, SettingsServiceError> {
        Ok(self.decode_stored::<EmailPolicySetting>().await?.inspect(
            EmailPolicySetting::default(),
            |value| value,
            EmailPolicySetting::validate,
        ))
    }

    pub async fn set_email_policy(
        &self,
        value: EmailPolicySetting,
    ) -> Result<EmailPolicySetting, SettingsServiceError> {
        let value = value.validate()?;
        repository::set_email_policy(&self.pool, &value).await?;
        Ok(value)
    }

    pub async fn set_email_policy_audited<F>(
        &self,
        value: EmailPolicySetting,
        audit: &AuditService,
        audit_event: F,
    ) -> Result<EmailPolicySetting, SettingsServiceError>
    where
        F: FnOnce(&EmailPolicySetting) -> AuditEvent,
    {
        self.set_email_policy_audited_if_generation(
            value,
            repository::get_generation(&self.pool, crate::settings::EMAIL_POLICY_KEY).await?,
            audit,
            audit_event,
        )
        .await
    }

    pub async fn set_email_policy_audited_if_generation<F>(
        &self,
        value: EmailPolicySetting,
        expected_generation: i64,
        audit: &AuditService,
        audit_event: F,
    ) -> Result<EmailPolicySetting, SettingsServiceError>
    where
        F: FnOnce(&EmailPolicySetting) -> AuditEvent,
    {
        let value = value.validate()?;
        let mut transaction = self.pool.begin().await?;
        let actual =
            repository::get_generation(&mut *transaction, crate::settings::EMAIL_POLICY_KEY)
                .await?;
        if actual != expected_generation {
            return Err(SettingsServiceError::Conflict);
        }
        repository::set_email_policy(&mut *transaction, &value).await?;
        audit
            .record_in_transaction(&mut transaction, audit_event(&value))
            .await?;
        transaction.commit().await?;
        Ok(value)
    }

    /// 公开注册开关的热路径读取：损坏或越界 fail-closed，与 email policy 同管道。
    ///
    /// 注册闸门（`users::service::registration::register`）与匿名状态端点都走这里；
    /// 管理读取走 [`Self::inspect_registration`]。
    pub async fn registration(&self) -> Result<RegistrationSetting, SettingsServiceError> {
        self.decode_stored::<RegistrationSetting>()
            .await?
            .require(
                RegistrationSetting::default(),
                |value| value,
                RegistrationSetting::validate,
            )
            .map_err(Self::persist_error::<RegistrationSetting>)
    }

    pub async fn inspect_registration(
        &self,
    ) -> Result<SettingInspection<RegistrationSetting>, SettingsServiceError> {
        Ok(self.decode_stored::<RegistrationSetting>().await?.inspect(
            RegistrationSetting::default(),
            |value| value,
            RegistrationSetting::validate,
        ))
    }

    pub async fn set_registration_audited<F>(
        &self,
        value: RegistrationSetting,
        audit: &AuditService,
        audit_event: F,
    ) -> Result<RegistrationSetting, SettingsServiceError>
    where
        F: FnOnce(&RegistrationSetting) -> AuditEvent,
    {
        let value = value.validate()?;
        let mut transaction = self.pool.begin().await?;
        repository::set_registration(&mut *transaction, &value).await?;
        audit
            .record_in_transaction(&mut transaction, audit_event(&value))
            .await?;
        transaction.commit().await?;
        Ok(value)
    }

    /// 单次数据库读取，不涉及缓存。
    ///
    /// 与 Passkey / email policy 同一条管道：无行用启动期环境配置（#361），
    /// 旧 schema 升级后校验，损坏或越界 fail-closed。调用方是 OAuth 授权、令牌
    /// 签发和限流器热路径——越界值不能再被 `sanitized()` 打扮成一次成功加载。
    /// 管理读取走 [`Self::inspect_security_limits`]，才能看见并修好当前行。
    pub(super) async fn load_security_limits(
        &self,
    ) -> Result<SecurityLimitsSetting, SettingsServiceError> {
        self.decode_stored::<SecurityLimitsSetting>()
            .await?
            .require(
                self.default_security_limits.clone(),
                |value| value,
                SecurityLimitsSetting::validate,
            )
            .map_err(Self::persist_error::<SecurityLimitsSetting>)
    }

    pub async fn inspect_security_limits(
        &self,
    ) -> Result<SettingInspection<SecurityLimitsSetting>, SettingsServiceError> {
        Ok(self
            .decode_stored::<SecurityLimitsSetting>()
            .await?
            .inspect(
                self.default_security_limits.clone(),
                |value| value,
                SecurityLimitsSetting::validate,
            ))
    }

    pub async fn session_lifetime(
        &self,
    ) -> Result<crate::settings::SessionLifetimeSetting, SettingsServiceError> {
        let value = self
            .decode_stored::<crate::settings::SessionLifetimeSetting>()
            .await?
            .require(
                crate::settings::SessionLifetimeSetting::default(),
                |value| value,
                crate::settings::SessionLifetimeSetting::validate,
            )
            .map_err(Self::persist_error::<crate::settings::SessionLifetimeSetting>)?;
        self.apply_session_lifetime_runtime(value.clone());
        Ok(value)
    }

    pub async fn inspect_session_lifetime(
        &self,
    ) -> Result<SettingInspection<crate::settings::SessionLifetimeSetting>, SettingsServiceError>
    {
        Ok(self
            .decode_stored::<crate::settings::SessionLifetimeSetting>()
            .await?
            .inspect(
                crate::settings::SessionLifetimeSetting::default(),
                |value| value,
                crate::settings::SessionLifetimeSetting::validate,
            ))
    }

    pub async fn set_session_lifetime(
        &self,
        value: crate::settings::SessionLifetimeSetting,
    ) -> Result<crate::settings::SessionLifetimeSetting, SettingsServiceError> {
        let value = value.validate()?;
        repository::set_session_lifetime(&self.pool, &value).await?;
        self.apply_session_lifetime_runtime(value.clone());
        Ok(value)
    }

    pub async fn set_session_lifetime_audited<F>(
        &self,
        value: crate::settings::SessionLifetimeSetting,
        audit: &AuditService,
        audit_event: F,
    ) -> Result<crate::settings::SessionLifetimeSetting, SettingsServiceError>
    where
        F: FnOnce(&crate::settings::SessionLifetimeSetting) -> AuditEvent,
    {
        let value = value.validate()?;
        let mut transaction = self.pool.begin().await?;
        repository::set_session_lifetime(&mut *transaction, &value).await?;
        audit
            .record_in_transaction(&mut transaction, audit_event(&value))
            .await?;
        transaction.commit().await?;
        self.apply_session_lifetime_runtime(value.clone());
        Ok(value)
    }

    fn passkey_runtime_default(&self) -> PasskeySetting {
        self.issuer_runtime
            .as_ref()
            .and_then(crate::settings::IssuerRuntime::current)
            .map(|snapshot| {
                PasskeySetting::default()
                    .with_runtime_defaults(snapshot.webauthn_rp_id(), snapshot.webauthn_origin())
            })
            .unwrap_or_else(|| self.default_passkey.clone())
    }

    async fn decode_stored<T: PersistedSetting>(
        &self,
    ) -> Result<PersistedDecode<T>, SettingsServiceError> {
        let raw = repository::get_text(&self.pool, T::KEY).await?;
        Ok(decode_persisted(raw.as_deref()))
    }

    fn persist_error<T: PersistedSetting>(error: PersistedLoadError) -> SettingsServiceError {
        match error {
            PersistedLoadError::Invalid(error) => SettingsServiceError::Validation(error),
            PersistedLoadError::Corrupt(_) => SettingsServiceError::Corrupt { key: T::KEY },
        }
    }
}

fn apply_passkey_runtime_defaults(
    value: PasskeySetting,
    runtime_default: &PasskeySetting,
) -> PasskeySetting {
    value.with_runtime_defaults(
        &runtime_default.rp_id,
        runtime_default
            .allowed_origins
            .first()
            .map(String::as_str)
            .unwrap_or_default(),
    )
}
