//! 创建/刷新调用提供方之后的错误收口。
//!
//! 提供方 `409 issuance_already_committed` / `refresh_already_committed` 表示对端
//! 已提交且不能重放 raw token，但这不是本地 lease 失败：同操作 ID 必须还能再探
//! 本地已提交结果。只有探不到密文时才对外 `reauthorization_required`。

use uuid::Uuid;

use super::ResourceServiceService;
use crate::resource_services::error::{ClientError, KnownErrorCode};
use crate::resource_services::service_error::ServiceError;
use crate::resource_services::types::BindingRow;
use crate::resource_services::views::BindingView;

pub(super) fn provider_already_committed(error: &ClientError) -> bool {
    matches!(
        error.provider_failure().map(|failure| failure.code),
        Some(KnownErrorCode::IssuanceAlreadyCommitted | KnownErrorCode::RefreshAlreadyCommitted)
    )
}

/// 终态失败才标记 lease。歧义响应、限流、不可用、以及提供方已提交都留下 lease，
/// 让同操作 ID 还能重试或再探本地结果。
pub(super) fn should_fail_operation(error: &ClientError) -> bool {
    match error {
        ClientError::Transport(_)
        | ClientError::ResponseTooLarge
        | ClientError::UnexpectedStatus(_)
        | ClientError::InvalidResponse(_) => false,
        ClientError::Provider(failure) => match failure.code {
            KnownErrorCode::IssuanceAlreadyCommitted
            | KnownErrorCode::RefreshAlreadyCommitted
            | KnownErrorCode::RateLimited
            | KnownErrorCode::ProviderUnavailable
            | KnownErrorCode::InvalidClient
            | KnownErrorCode::InvalidRequest => false,
            KnownErrorCode::CredentialInvalid
            | KnownErrorCode::InvalidRefreshToken
            | KnownErrorCode::InvalidAccessToken
            | KnownErrorCode::AccountDisabled
            | KnownErrorCode::AccountNotFound
            | KnownErrorCode::BindingConflict => true,
        },
    }
}

fn recovered_committed_row(row: &BindingRow, observed_generation: i64) -> bool {
    row.is_live() && row.generation > observed_generation && row.token_bundle_ciphertext.is_some()
}

impl ResourceServiceService {
    pub(super) async fn handle_provider_error(
        &self,
        provider_id: Uuid,
        operation_type: &str,
        idempotency_key: Uuid,
        binding_id: Uuid,
        observed_generation: i64,
        error: ClientError,
    ) -> Result<BindingView, ServiceError> {
        // 对外统一收口为 provider_unavailable 等稳定错误码，但运维需要能区分
        // 「连不上 / 对端拒绝 / 协议不合」；错误 Display 只含分类与状态码，不含凭据。
        tracing::warn!(
            provider_id = %provider_id,
            operation = operation_type,
            binding_id = %binding_id,
            error = %error,
            "resource service provider call failed"
        );
        if provider_already_committed(&error) {
            if let Some(view) = self
                .probe_committed_binding(binding_id, observed_generation)
                .await?
            {
                return Ok(view);
            }
            return Err(ServiceError::ReauthorizationRequired);
        }
        if should_fail_operation(&error) {
            self.fail_operation(provider_id, operation_type, idempotency_key)
                .await?;
        }
        Err(ServiceError::from(error))
    }

    async fn probe_committed_binding(
        &self,
        binding_id: Uuid,
        observed_generation: i64,
    ) -> Result<Option<BindingView>, ServiceError> {
        let Some(row) = self.store.get_binding(binding_id).await? else {
            return Ok(None);
        };
        if recovered_committed_row(&row, observed_generation) {
            return Ok(Some(BindingView::from_row(&row)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_services::error::ProtocolError;
    use crate::resource_services::error::ProviderFailure;
    use crate::resource_services::transport::TransportError;
    use serde_json::json;
    use time::OffsetDateTime;

    fn provider(code: KnownErrorCode) -> ClientError {
        ClientError::Provider(ProviderFailure {
            code,
            retry_after: None,
        })
    }

    #[test]
    fn already_committed_codes_are_not_local_lease_failures() {
        for code in [
            KnownErrorCode::IssuanceAlreadyCommitted,
            KnownErrorCode::RefreshAlreadyCommitted,
        ] {
            let error = provider(code);
            assert!(provider_already_committed(&error));
            assert!(!should_fail_operation(&error));
        }
    }

    #[test]
    fn retryable_and_ambiguous_errors_keep_the_lease() {
        assert!(!should_fail_operation(&provider(
            KnownErrorCode::RateLimited
        )));
        assert!(!should_fail_operation(&provider(
            KnownErrorCode::ProviderUnavailable
        )));
        assert!(!should_fail_operation(&provider(
            KnownErrorCode::InvalidClient
        )));
        assert!(!should_fail_operation(&provider(
            KnownErrorCode::InvalidRequest
        )));
        assert!(!should_fail_operation(&ClientError::ResponseTooLarge));
        assert!(!should_fail_operation(&ClientError::UnexpectedStatus(502)));
        assert!(!should_fail_operation(&ClientError::Transport(
            TransportError::Timeout
        )));
        assert!(!should_fail_operation(&ClientError::InvalidResponse(
            ProtocolError::MalformedJson
        )));
    }

    #[test]
    fn terminal_provider_codes_fail_the_lease() {
        for code in [
            KnownErrorCode::CredentialInvalid,
            KnownErrorCode::InvalidRefreshToken,
            KnownErrorCode::InvalidAccessToken,
            KnownErrorCode::AccountDisabled,
            KnownErrorCode::AccountNotFound,
            KnownErrorCode::BindingConflict,
        ] {
            assert!(
                should_fail_operation(&provider(code)),
                "{code:?} should fail the lease"
            );
            assert!(!provider_already_committed(&provider(code)));
        }
    }

    #[test]
    fn local_commit_is_recovered_only_after_generation_advances_with_ciphertext() {
        let now = OffsetDateTime::now_utc();
        let mut row = BindingRow {
            id: Uuid::nil(),
            provider_id: Uuid::nil(),
            user_id: 1,
            uid: "uid".to_owned(),
            issuer: "https://provider.example".to_owned(),
            grant_id: None,
            grant_expires_at: None,
            generation: 1,
            tombstoned_at: None,
            token_bundle_ciphertext: None,
            snapshot_json: json!({}),
            access_expires_at: None,
            refresh_expires_at: None,
            created_at: now,
            updated_at: now,
        };
        assert!(!recovered_committed_row(&row, 1));
        row.token_bundle_ciphertext = Some("cipher".to_owned());
        assert!(!recovered_committed_row(&row, 1));
        row.generation = 2;
        assert!(recovered_committed_row(&row, 1));
        row.tombstoned_at = Some(now);
        assert!(!recovered_committed_row(&row, 1));
    }
}
