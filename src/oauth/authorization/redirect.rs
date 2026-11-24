use super::{AuthorizationRequest, AuthorizationRequestError, RegisteredClient};
use crate::clients::domain::canonicalize_redirect_uri;
use url::{Host, Url};

/// 授权成功和错误回跳共用完整校验，避免错误路径接受成功路径拒绝的回调。
pub(crate) fn validate_client_and_redirect_uri(
    client: &RegisteredClient,
    request: &AuthorizationRequest,
) -> Result<String, AuthorizationRequestError> {
    if request.client_id != client.client_id {
        return Err(AuthorizationRequestError::InvalidClient);
    }
    let canonical_redirect_uri = canonicalize_redirect_uri(&request.redirect_uri)
        .ok_or(AuthorizationRequestError::RedirectUriNotAllowed)?;
    if !client
        .redirect_uris
        .iter()
        .any(|uri| redirect_uri_matches(uri, &canonical_redirect_uri))
        || !numeric_app_callback_allowed(&canonical_redirect_uri, client.numeric_app_id)
    {
        return Err(AuthorizationRequestError::RedirectUriNotAllowed);
    }
    Ok(canonical_redirect_uri)
}

/// App Link 回调路径 `/app/<numeric_app_id>/oauth/callback` 必须属于当前应用。
/// 普通回调不受数字应用 ID 限制；查询参数和片段不参与路径识别。
fn numeric_app_callback_allowed(canonical_redirect_uri: &str, numeric_app_id: i64) -> bool {
    let Ok(url) = Url::parse(canonical_redirect_uri) else {
        return false;
    };
    let Some(digits) = url.path().strip_prefix("/app/").and_then(|rest| {
        rest.strip_suffix("/oauth/callback").filter(|digits| {
            !digits.is_empty()
                && !digits.contains('/')
                && digits.bytes().all(|b| b.is_ascii_digit())
        })
    }) else {
        return true;
    };
    digits
        .parse::<i64>()
        .is_ok_and(|parsed| parsed == numeric_app_id)
}

/// RFC 8252 §7.3 允许原生应用的字面量回环地址仅改变端口。
/// 其他回调仍在规范化后精确匹配，不接受主机、路径或查询参数的变化。
pub(crate) fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }

    let (Ok(registered_url), Ok(requested_url)) = (Url::parse(registered), Url::parse(requested))
    else {
        return false;
    };
    if registered_url.as_str() != registered || requested_url.as_str() != requested {
        return false;
    }
    if registered_url.scheme() != "http" || requested_url.scheme() != "http" {
        return false;
    }

    let same_literal_loopback_ip = match (registered_url.host(), requested_url.host()) {
        (Some(Host::Ipv4(registered_ip)), Some(Host::Ipv4(requested_ip))) => {
            registered_ip.is_loopback() && registered_ip == requested_ip
        }
        (Some(Host::Ipv6(registered_ip)), Some(Host::Ipv6(requested_ip))) => {
            registered_ip.is_loopback() && registered_ip == requested_ip
        }
        _ => false,
    };

    same_literal_loopback_ip
        && registered_url.username().is_empty()
        && requested_url.username().is_empty()
        && registered_url.password().is_none()
        && requested_url.password().is_none()
        && registered_url.path() == requested_url.path()
        && registered_url.query() == requested_url.query()
        && registered_url.fragment().is_none()
        && requested_url.fragment().is_none()
}
