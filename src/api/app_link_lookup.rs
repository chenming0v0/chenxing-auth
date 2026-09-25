//! 按数字 App ID 公开查询已发布的 Android 包名。
//!
//! 与 `/.well-known/assetlinks.json` 一样挂在 Issuer 门禁之外。授权确认页用这个
//! 包名构造 `intent://`，不读取请求里的 Host 或包名。

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
struct AppLinkLookupResponse {
    numeric_app_id: i64,
    package_name: String,
}

pub async fn lookup_app_link(
    State(state): State<AppState>,
    Path(numeric_app_id): Path<String>,
) -> Response {
    let Some(numeric_app_id) = positive_numeric_app_id(&numeric_app_id) else {
        return app_link_not_found();
    };
    match state.clients.active_app_link_package(numeric_app_id).await {
        Ok(Some(package_name)) => (
            StatusCode::OK,
            [(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            )],
            Json(AppLinkLookupResponse {
                numeric_app_id,
                package_name,
            }),
        )
            .into_response(),
        Ok(None) => app_link_not_found(),
        Err(_) => {
            tracing::error!("failed to read published Android app link");
            crate::error::service_unavailable(
                "app_link_unavailable",
                "Android App Link storage is unavailable",
            )
        }
    }
}

fn app_link_not_found() -> Response {
    crate::error::not_found(
        "app_link_not_found",
        "published Android App Link was not found",
    )
}

/// 只接受十进制正整数。前导零按数值折叠（`01` 即 `1`）；零、负数和非数字都不是。
fn positive_numeric_app_id(value: &str) -> Option<i64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<i64>().ok().filter(|id| *id > 0)
}

#[cfg(test)]
mod tests {
    use super::positive_numeric_app_id;

    #[test]
    fn positive_numeric_app_id_accepts_only_decimal_above_zero() {
        assert_eq!(positive_numeric_app_id("1"), Some(1));
        assert_eq!(positive_numeric_app_id("42"), Some(42));
        assert_eq!(positive_numeric_app_id("01"), Some(1));
        assert_eq!(positive_numeric_app_id("0"), None);
        assert_eq!(positive_numeric_app_id("-1"), None);
        assert_eq!(positive_numeric_app_id("not-a-number"), None);
        assert_eq!(positive_numeric_app_id(""), None);
        assert_eq!(positive_numeric_app_id("9223372036854775808"), None);
    }
}
