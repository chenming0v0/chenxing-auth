//! Payload loading for claimed email outbox entries.
//!
//! Every read re-checks the claim fence (`claim_generation` + `claim_token`)
//! and the business preconditions of the entry kind, so a reclaimed lease can
//! never resurrect a message whose challenge was consumed, expired or whose
//! user was disabled in the meantime.

use zeroize::Zeroizing;

use super::{
    EmailOutbox, EmailOutboxError, OutboxEntry, SECURITY_ALERT_KIND, VERIFICATION_CODE_KIND,
};
use crate::{
    notifications::{EmailMessage, crypto::decrypt_code},
    sqlx::{Postgres, Transaction},
};

impl EmailOutbox {
    pub(super) async fn load_message(
        &self,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, entry.user_id)
            .await
            .map_err(EmailOutboxError::Database)?;
        let message = self
            .load_message_in_transaction(&mut transaction, entry)
            .await?;
        if message.is_none() {
            self.mark_cancelled(&mut transaction, entry).await?;
        }
        transaction
            .commit()
            .await
            .map_err(EmailOutboxError::Database)?;
        Ok(message)
    }

    async fn load_message_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        match entry.kind.as_str() {
            VERIFICATION_CODE_KIND => self.load_verification_message(transaction, entry).await,
            SECURITY_ALERT_KIND => self.load_security_alert_message(transaction, entry).await,
            _ => Err(EmailOutboxError::InvalidPayload),
        }
    }

    async fn load_verification_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let row: Option<(String, Option<Vec<u8>>)> = crate::sqlx::query_as(
            "SELECT challenge.new_email, outbox.encrypted_code
             FROM email_outbox AS outbox
             JOIN user_email_change_challenges AS challenge
               ON challenge.id = outbox.challenge_id
             JOIN users ON users.id = outbox.user_id
             WHERE outbox.id = $1
               AND outbox.user_id = $2
               AND outbox.challenge_id = $3
               AND outbox.kind = $6
               AND outbox.processed_at IS NULL
               AND outbox.cancelled_at IS NULL
               AND outbox.dead_lettered_at IS NULL
               AND outbox.claim_generation = $4
               AND outbox.claim_token = $5
               AND challenge.consumed_at IS NULL
               AND challenge.expires_at > NOW()
               AND challenge.security_epoch = users.session_epoch
               AND users.status = 'active'
              FOR UPDATE OF outbox",
        )
        .bind(entry.id)
        .bind(entry.user_id)
        .bind(entry.challenge_id)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .bind(VERIFICATION_CODE_KIND)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        let Some((recipient, encrypted_code)) = row else {
            return Ok(None);
        };
        let encrypted_code = encrypted_code.ok_or(EmailOutboxError::InvalidPayload)?;
        let code = decrypt_code(
            &self.encryption_keys,
            encrypted_code.as_slice(),
            entry.user_id,
            entry.challenge_id,
        )
        .map_err(|_| EmailOutboxError::Decryption)?;
        if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
            return Err(EmailOutboxError::InvalidCode);
        }
        let code = Zeroizing::new(
            String::from_utf8(code.to_vec()).map_err(|_| EmailOutboxError::InvalidCode)?,
        );
        let recipient = crate::users::email::EmailAddress::parse(&recipient)
            .map_err(|_| EmailOutboxError::InvalidRecipient)?;
        Ok(Some(EmailMessage {
            to: recipient,
            subject: "辰星通行证邮箱变更验证码".to_owned(),
            body: format!(
                "你的邮箱变更验证码是：{}\n验证码将在 10 分钟后失效。",
                code.as_str()
            ),
        }))
    }

    async fn load_security_alert_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let recipient: Option<String> = crate::sqlx::query_scalar(
            "SELECT outbox.recipient
             FROM email_outbox AS outbox
             JOIN user_email_change_challenges AS challenge
               ON challenge.id = outbox.challenge_id
             WHERE outbox.id = $1
               AND outbox.user_id = $2
               AND outbox.challenge_id = $3
               AND outbox.kind = $4
               AND outbox.processed_at IS NULL
               AND outbox.cancelled_at IS NULL
               AND outbox.dead_lettered_at IS NULL
               AND outbox.claim_generation = $5
               AND outbox.claim_token = $6
               AND challenge.consumed_at IS NOT NULL
              FOR UPDATE OF outbox",
        )
        .bind(entry.id)
        .bind(entry.user_id)
        .bind(entry.challenge_id)
        .bind(SECURITY_ALERT_KIND)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        let Some(recipient) = recipient else {
            return Ok(None);
        };
        let recipient = crate::users::email::EmailAddress::parse(&recipient)
            .map_err(|_| EmailOutboxError::InvalidRecipient)?;
        Ok(Some(EmailMessage {
            to: recipient,
            subject: "辰星通行证邮箱已变更".to_owned(),
            body: "你的账户邮箱已变更。如果这不是你的操作，请立即联系管理员。".to_owned(),
        }))
    }
}
