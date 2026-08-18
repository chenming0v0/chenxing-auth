//! 公开注册开关的读取边界（与 [`email_policy`](super::email_policy) 同构）。
//!
//! 注册闸门在 `users::service::registration::register` 内执行；本模块只负责把
//! `app_settings` 里的 `registration` 行解析成 [`RegistrationSetting`]，并区分
//! 「未配置」与「不可读」两种语义——二者都收敛到同一份默认值，而默认值恰好是
//! 双 false 的关闭态，因此不可读时回退默认就是 fail-closed，不存在第三种放行态。

use crate::settings::{
    REGISTRATION_SETTING_KEY, RegistrationSetting,
    persisted::{PersistedDecode, decode_persisted},
};
use crate::sqlx::PgPool;

/// 读取公开注册设置。
///
/// - 行缺失或空白：管理员从未写入，使用 [`RegistrationSetting::default()`]
///   （注册关闭）是合法初始状态。
/// - 行存在但 decode 失败：结构漂移或损坏。回退到默认值即「注册关闭」，
///   与 email policy 的 fail-closed 边界一致；损坏细节只进日志，不外泄。
pub(super) async fn load_registration_setting(
    pool: &PgPool,
) -> Result<RegistrationSetting, crate::sqlx::Error> {
    let raw = crate::settings::repository::get_text(pool, REGISTRATION_SETTING_KEY).await?;
    Ok(
        match decode_persisted::<RegistrationSetting>(raw.as_deref()) {
            PersistedDecode::Decoded(value) => value,
            PersistedDecode::Unconfigured => RegistrationSetting::default(),
            PersistedDecode::Corrupt(error) => {
                tracing::error!(
                    setting_key = REGISTRATION_SETTING_KEY,
                    error = %error,
                    "stored registration setting is unreadable; failing closed with registration disabled"
                );
                RegistrationSetting::default()
            }
        },
    )
}
