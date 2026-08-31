use super::*;

impl SettingsService {
    pub async fn smtp(&self) -> Result<SmtpSetting, SettingsServiceError> {
        Ok(match repository::get_smtp(&self.pool).await? {
            Some(stored) => SmtpSetting {
                host: stored.host,
                port: stored.port,
                username: stored.username,
                from_address: stored.from_address,
                ssl_enabled: stored.ssl_enabled,
                force_auth_login: stored.force_auth_login,
                password_configured: stored
                    .password_ciphertext
                    .as_ref()
                    .is_some_and(|value| !value.is_empty()),
            },
            None => {
                let mut setting = SmtpSetting::default();
                if let Some(from) = repository::get_registration_email_from(&self.pool).await? {
                    setting.from_address = from;
                }
                setting
            }
        })
    }

    pub async fn set_smtp(
        &self,
        update: SmtpSettingUpdate,
    ) -> Result<(SmtpSetting, SmtpPasswordAction), SettingsServiceError> {
        let mut transaction = self.pool.begin().await?;
        let result = self.persist_smtp(&mut transaction, update).await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn set_smtp_audited<F>(
        &self,
        update: SmtpSettingUpdate,
        audit: &AuditService,
        credential: ManagementActorCredential,
        audit_event: F,
    ) -> Result<(SmtpSetting, SmtpPasswordAction), SettingsServiceError>
    where
        F: FnOnce(&(SmtpSetting, SmtpPasswordAction)) -> AuditEvent,
    {
        let mut transaction = self.pool.begin().await?;
        crate::users::repository::management_actor::validate_management_actor_in_transaction(
            &mut transaction,
            credential,
            UserPermission::ManageSystemSettings,
        )
        .await?;
        let result = self.persist_smtp(&mut transaction, update).await?;
        audit
            .record_in_transaction(&mut transaction, audit_event(&result))
            .await?;
        transaction.commit().await?;
        Ok(result)
    }

    async fn persist_smtp(
        &self,
        transaction: &mut crate::sqlx::Transaction<'_, crate::sqlx::Postgres>,
        update: SmtpSettingUpdate,
    ) -> Result<(SmtpSetting, SmtpPasswordAction), SettingsServiceError> {
        let (mut setting, password) = update.validate()?;
        let password_action = password.action();
        // SMTP 与注册发件人镜像必须一起落库：第二次写失败时若第一个键已持久化
        // 会形成「SMTP 已更新、镜像残留旧地址」的半同步状态（#322）。
        // 事务开始后先按统一顺序锁两个键；keep/clear 基于锁内 SMTP 快照处理密文。
        let existing = repository::lock_registration_email_and_smtp(transaction).await?;
        let password_ciphertext = password.next_ciphertext(
            existing
                .as_ref()
                .and_then(|value| value.password_ciphertext.clone()),
            |plaintext| {
                self.secrets
                    .encrypt_for(SecretContext::Smtp, &plaintext)
                    .map(|secret| SecretManager::encode(&secret))
            },
        )?;
        setting.password_configured = password_ciphertext
            .as_ref()
            .is_some_and(|value| !value.is_empty());
        let stored = StoredSmtpSetting {
            host: setting.host.clone(),
            port: setting.port,
            username: setting.username.clone(),
            from_address: setting.from_address.clone(),
            ssl_enabled: setting.ssl_enabled,
            force_auth_login: setting.force_auth_login,
            password_ciphertext,
        };
        repository::set_smtp(&mut **transaction, &stored).await?;
        // 镜像同步必须双向（#321）：非空 from 写入独立键；from 清空时删除该键。
        // `validate` 已保证非空 from 可解析，`None` 分支只可能来自显式清空。只写
        // 不删会让读取路径（`registration_email_from`，SMTP from 为空时回退到独立
        // 键）命中残留旧地址，已停用的发件人在注册邮件里复活；与
        // `set_registration_email_from` 清除时同步清 SMTP from 的方向对称。
        match extract_email(&setting.from_address) {
            Some(email) => {
                repository::set_registration_email_from(&mut **transaction, Some(&email)).await?
            }
            None => repository::set_registration_email_from(&mut **transaction, None).await?,
        }
        Ok((setting, password_action))
    }
}

/// 发件人邮箱的规范化。
///
/// 走 [`EmailAddress`] 这一个入口（Issue #302），取展示值：这个地址会进入 SMTP
/// 的 `From` 头，需要的是给人看的形态，而域名已经被规范化成可传输的 ASCII。
/// 它不是账号标识符，因此不需要匹配值。
pub(super) fn normalize_email(
    value: Option<String>,
) -> Result<Option<String>, SettingsServiceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    EmailAddress::parse(&value)
        .map(|email| Some(email.into_display()))
        .map_err(|_| SettingsServiceError::InvalidEmail)
}

/// 从 `Name <a@b>` 或裸邮箱里取出规范化后的展示值。
pub(super) fn extract_email(value: &str) -> Option<String> {
    parse_smtp_sender(value).map(EmailAddress::into_display)
}
