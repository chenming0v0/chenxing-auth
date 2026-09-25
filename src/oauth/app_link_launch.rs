//! 判断待确认授权的回调是不是本 Issuer 上的 Android App Link。
//!
//! Chrome 不会把同主机的渲染器导航交给 App。前端只有在这里拿到包名时，才用
//! `intent://` 按包名显式唤起；其它回调不返回包名。

use crate::config::IssuerUrl;

use super::authorization::RegisteredClient;

/// 回调同时满足下列条件时返回包名，否则 `None`：
///
/// - `redirect_uri` 能解析，且 scheme 是 `https`
/// - host 与端口都等于 Issuer（含 scheme 的默认端口）
/// - path 正好是 `/app/{numeric_app_id}/oauth/callback`
/// - Client 已发布 Android 包名
///
/// 端口必须用 [`url::Url::port_or_known_default`]：[`url::Url::port`] 会把
/// http 的 80 和 https 的 443 都藏成 `None`，两种 scheme 会被误判成同一端口。
pub(crate) fn android_launch_package(
    issuer_host_url: &IssuerUrl,
    client: &RegisteredClient,
    redirect_uri: &str,
) -> Option<String> {
    let package = client.android_package.as_deref()?;
    let redirect = url::Url::parse(redirect_uri).ok()?;
    if redirect.scheme() != "https" {
        return None;
    }
    let issuer = issuer_host_url.parsed();
    if redirect.host() != issuer.host()
        || redirect.port_or_known_default() != issuer.port_or_known_default()
    {
        return None;
    }
    let expected_path = format!("/app/{}/oauth/callback", client.numeric_app_id);
    if redirect.path() != expected_path {
        return None;
    }
    Some(package.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(value: &str) -> IssuerUrl {
        IssuerUrl::parse(value).expect("issuer url")
    }

    fn client(numeric_app_id: i64, package: Option<&str>) -> RegisteredClient {
        RegisteredClient {
            client_id: "client-1".to_owned(),
            client_name: "Test Client".to_owned(),
            redirect_uris: Vec::new(),
            scopes: vec!["openid".to_owned()],
            owner_user_id: None,
            logo_uri: None,
            client_uri: None,
            description: None,
            numeric_app_id,
            android_package: package.map(str::to_owned),
            quota_exempt: false,
        }
    }

    #[test]
    fn matching_issuer_app_link_returns_the_package() {
        let issuer = issuer("https://auth.example");
        let client = client(7, Some("com.chengming.termux"));
        assert_eq!(
            android_launch_package(
                &issuer,
                &client,
                "https://auth.example/app/7/oauth/callback",
            )
            .as_deref(),
            Some("com.chengming.termux")
        );
        assert_eq!(
            android_launch_package(
                &issuer,
                &client,
                "https://auth.example:443/app/7/oauth/callback",
            )
            .as_deref(),
            Some("com.chengming.termux")
        );
    }

    #[test]
    fn other_host_is_not_an_issuer_app_link() {
        assert!(
            android_launch_package(
                &issuer("https://auth.example"),
                &client(7, Some("com.chengming.termux")),
                "https://other.example/app/7/oauth/callback",
            )
            .is_none()
        );
    }

    #[test]
    fn other_numeric_id_is_not_this_client() {
        assert!(
            android_launch_package(
                &issuer("https://auth.example"),
                &client(7, Some("com.chengming.termux")),
                "https://auth.example/app/8/oauth/callback",
            )
            .is_none()
        );
    }

    #[test]
    fn http_scheme_is_rejected() {
        assert!(
            android_launch_package(
                &issuer("https://auth.example"),
                &client(7, Some("com.chengming.termux")),
                "http://auth.example/app/7/oauth/callback",
            )
            .is_none()
        );
    }

    #[test]
    fn missing_package_returns_none() {
        assert!(
            android_launch_package(
                &issuer("https://auth.example"),
                &client(7, None),
                "https://auth.example/app/7/oauth/callback",
            )
            .is_none()
        );
    }

    #[test]
    fn trailing_slash_is_rejected() {
        assert!(
            android_launch_package(
                &issuer("https://auth.example"),
                &client(7, Some("com.chengming.termux")),
                "https://auth.example/app/7/oauth/callback/",
            )
            .is_none()
        );
    }

    #[test]
    fn http_issuer_default_port_does_not_match_https_callback() {
        assert!(
            android_launch_package(
                &issuer("http://127.0.0.1"),
                &client(7, Some("com.chengming.termux")),
                "https://127.0.0.1/app/7/oauth/callback",
            )
            .is_none()
        );
    }

    #[test]
    fn non_default_port_must_match_exactly() {
        let issuer = issuer("https://auth.example:8443");
        let client = client(7, Some("com.chengming.termux"));
        assert_eq!(
            android_launch_package(
                &issuer,
                &client,
                "https://auth.example:8443/app/7/oauth/callback",
            )
            .as_deref(),
            Some("com.chengming.termux")
        );
        assert!(
            android_launch_package(
                &issuer,
                &client,
                "https://auth.example/app/7/oauth/callback",
            )
            .is_none()
        );
    }
}
