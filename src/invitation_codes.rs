use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    audit::{AuditError, AuditEvent},
    sqlx::PgPool,
    users::{ManagementActorCredential, ManagementActorValidationError, domain::UserPermission},
};

const MAX_BATCH_SIZE: u16 = 100;

#[derive(Debug, Deserialize)]
pub struct CreateInvitationCodesInput {
    pub count: u16,
    pub max_uses: i32,
    pub expires_at: Option<OffsetDateTime>,
    pub label: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvitationCodeError {
    #[error("invitation code request is invalid")]
    InvalidInput,
    #[error("invitation code was not found")]
    NotFound,
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    ManagementActor(#[from] ManagementActorValidationError),
    #[error(transparent)]
    Database(#[from] crate::sqlx::Error),
}

#[derive(Debug, Serialize)]
pub struct InvitationCodeSummary {
    pub id: i64,
    pub label: Option<String>,
    pub max_uses: i32,
    pub use_count: i32,
    pub expires_at: Option<OffsetDateTime>,
    pub disabled_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

type InvitationCodeRow = (
    i64,
    Option<String>,
    i32,
    i32,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    OffsetDateTime,
);

fn summary(row: InvitationCodeRow) -> InvitationCodeSummary {
    InvitationCodeSummary {
        id: row.0,
        label: row.1,
        max_uses: row.2,
        use_count: row.3,
        expires_at: row.4,
        disabled_at: row.5,
        created_at: row.6,
    }
}

#[derive(Debug, Serialize)]
pub struct CreatedInvitationCode {
    #[serde(flatten)]
    pub summary: InvitationCodeSummary,
    pub code: String,
}

pub fn digest(code: &str) -> [u8; 32] {
    Sha256::digest(code.trim().as_bytes()).into()
}

fn generate_code() -> String {
    let mut random = [0_u8; 24];
    OsRng.fill_bytes(&mut random);
    format!("cxi_{}", URL_SAFE_NO_PAD.encode(random))
}

fn validate_input(
    mut input: CreateInvitationCodesInput,
) -> Result<CreateInvitationCodesInput, InvitationCodeError> {
    if input.count == 0
        || input.count > MAX_BATCH_SIZE
        || !(1..=10_000).contains(&input.max_uses)
        || input
            .expires_at
            .is_some_and(|value| value <= OffsetDateTime::now_utc())
    {
        return Err(InvitationCodeError::InvalidInput);
    }
    input.label = input.label.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    });
    if input
        .label
        .as_ref()
        .is_some_and(|value| value.chars().count() > 128)
    {
        return Err(InvitationCodeError::InvalidInput);
    }
    Ok(input)
}

pub async fn create_batch_with_audit(
    pool: &PgPool,
    input: CreateInvitationCodesInput,
    created_by: Option<i64>,
    credential: ManagementActorCredential,
    audit_event: impl FnOnce(&[CreatedInvitationCode]) -> AuditEvent,
) -> Result<Vec<CreatedInvitationCode>, InvitationCodeError> {
    let input = validate_input(input)?;
    let mut transaction = pool.begin().await?;
    crate::users::repository::management_actor::validate_management_actor_in_transaction(
        &mut transaction,
        credential,
        UserPermission::ManageSettings,
    )
    .await?;
    let mut created = Vec::with_capacity(input.count.into());
    for _ in 0..input.count {
        let code = generate_code();
        let row: InvitationCodeRow = crate::sqlx::query_as(
            "INSERT INTO registration_invitation_codes (code_digest, label, max_uses, expires_at, created_by)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, label, max_uses, use_count, expires_at, disabled_at, created_at",
        )
        .bind(digest(&code).as_slice()).bind(&input.label).bind(input.max_uses)
        .bind(input.expires_at).bind(created_by).fetch_one(&mut *transaction).await?;
        created.push(CreatedInvitationCode {
            summary: summary(row),
            code,
        });
    }
    crate::audit::repository::insert_with(&mut *transaction, &audit_event(&created)).await?;
    transaction.commit().await?;
    Ok(created)
}

pub async fn list(pool: &PgPool) -> Result<Vec<InvitationCodeSummary>, crate::sqlx::Error> {
    let rows: Vec<InvitationCodeRow> = crate::sqlx::query_as(
        "SELECT id, label, max_uses, use_count, expires_at, disabled_at, created_at
         FROM registration_invitation_codes ORDER BY created_at DESC, id DESC LIMIT 500",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(summary).collect())
}

pub async fn disable_with_audit(
    pool: &PgPool,
    id: i64,
    credential: ManagementActorCredential,
    audit_event: AuditEvent,
) -> Result<InvitationCodeSummary, InvitationCodeError> {
    let mut transaction = pool.begin().await?;
    crate::users::repository::management_actor::validate_management_actor_in_transaction(
        &mut transaction,
        credential,
        UserPermission::ManageSettings,
    )
    .await?;
    let row: InvitationCodeRow = crate::sqlx::query_as(
        "UPDATE registration_invitation_codes SET disabled_at = COALESCE(disabled_at, NOW()) WHERE id = $1
         RETURNING id, label, max_uses, use_count, expires_at, disabled_at, created_at",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(InvitationCodeError::NotFound)?;
    crate::audit::repository::insert_with(&mut *transaction, &audit_event).await?;
    transaction.commit().await?;
    Ok(summary(row))
}

pub async fn invitation_id_for_user(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<i64>, crate::sqlx::Error> {
    crate::sqlx::query_scalar(
        "SELECT invitation_id FROM registration_invitation_uses WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}
