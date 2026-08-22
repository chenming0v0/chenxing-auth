use crate::clients::domain::ClientAuthMethod;
use crate::sqlx::PgPool;
use crate::users::domain::UserId;

#[path = "repository_core.rs"]
mod core;
pub(super) use core::insert_client_row;
pub use core::{
    AuditedClientInsertError, ClientCredential, ClientInsertError, ListedClient, NewClient,
    NewOwnedClient, StoredClient, count_clients, find_client_by_id, insert_client,
    insert_client_with_audit, list_clients, query_clients,
};
#[path = "repository_mutation.rs"]
mod mutation;
pub use mutation::{
    set_client_status, set_client_status_with_audit, update_client, update_client_with_audit,
};

#[path = "repository_credentials.rs"]
mod credentials;
pub use credentials::{
    StoredClientCredentials, find_client_credentials, lock_client_credentials_if_version,
};
#[path = "repository_rotation.rs"]
mod rotation;
pub use rotation::{
    AuditedRotationError, find_client_secret_version, update_client_secret_if_version,
    update_client_secret_if_version_with_audit,
};
#[path = "repository_owned_registration.rs"]
mod owned_registration;
pub use owned_registration::{insert_owned_client, insert_owned_client_with_audit};
#[path = "repository_idempotency.rs"]
mod idempotency;
pub(crate) use idempotency::{
    IdempotentClientInsert, IdempotentClientOperationError, IdempotentClientRotation,
    insert_client_idempotent_with_audit, rotate_client_secret_idempotent_with_audit,
};

#[derive(Debug, thiserror::Error)]
pub enum AuditedClientMutationError {
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("audit operation failed: {0}")]
    Audit(#[from] crate::audit::AuditError),
}

/// 轮换 Client Secret 的兼容入口。
///
/// 保留既有签名，但先读取版本再执行 CAS，避免旧调用方继续触发 LWW。
pub async fn update_client_secret(
    pool: &crate::sqlx::PgPool,
    owner_user_id: Option<crate::users::domain::UserId>,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<bool, crate::sqlx::Error> {
    let Some(expected_version) = find_client_secret_version(pool, owner_user_id, client_id).await?
    else {
        return Ok(false);
    };
    update_client_secret_if_version(
        pool,
        owner_user_id,
        client_id,
        expected_version,
        client_secret_hash,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_credential_carries_no_secret_hash() {
        let credential = ClientCredential::Public;
        assert_eq!(credential.auth_method(), ClientAuthMethod::None);
        assert_eq!(credential.secret_hash(), None);
    }

    #[test]
    fn confidential_credentials_map_to_matching_auth_method() {
        let basic = ClientCredential::SecretBasic("hash-basic".to_owned());
        assert_eq!(basic.auth_method(), ClientAuthMethod::Basic);
        assert_eq!(basic.secret_hash(), Some("hash-basic"));

        let post = ClientCredential::SecretPost("hash-post".to_owned());
        assert_eq!(post.auth_method(), ClientAuthMethod::Post);
        assert_eq!(post.secret_hash(), Some("hash-post"));
    }

    #[test]
    fn credential_auth_method_values_match_database_check_constraint() {
        for credential in [
            ClientCredential::SecretBasic("hash".to_owned()),
            ClientCredential::SecretPost("hash".to_owned()),
            ClientCredential::Public,
        ] {
            assert!(matches!(
                credential.auth_method().as_str(),
                "client_secret_basic" | "client_secret_post" | "none"
            ));
        }
    }
}
