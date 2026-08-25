//! RFC 7591 / OIDC DCR 展示元数据校验。
//!
//! `logo_uri` 和 `client_uri` 只给同意屏看，不参与令牌交换。服务端只校验 URL
//! 形态，不拉取内容，避免把用户可控地址变成 SSRF。

use url::Url;

use super::domain::ClientRegistrationError;

pub const MAX_PRESENTATION_URI_LENGTH: usize = 2_048;

pub fn validate_logo_uri(value: Option<String>) -> Result<Option<String>, ClientRegistrationError> {
    validate_https_uri(value, PresentationField::Logo)
}

pub fn validate_client_uri(
    value: Option<String>,
) -> Result<Option<String>, ClientRegistrationError> {
    validate_https_uri(value, PresentationField::Client)
}

#[derive(Clone, Copy)]
enum PresentationField {
    Logo,
    Client,
}

impl PresentationField {
    fn invalid(self) -> ClientRegistrationError {
        match self {
            Self::Logo => ClientRegistrationError::InvalidLogoUri,
            Self::Client => ClientRegistrationError::InvalidClientUri,
        }
    }
}

fn validate_https_uri(
    value: Option<String>,
    field: PresentationField,
) -> Result<Option<String>, ClientRegistrationError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_PRESENTATION_URI_LENGTH || trimmed.contains('*') {
        return Err(field.invalid());
    }
    let url = Url::parse(trimmed).map_err(|_| field.invalid())?;
    if url.scheme() != "https" {
        return Err(field.invalid());
    }
    if url.host_str().is_none()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(field.invalid());
    }
    Ok(Some(url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_values_become_none() {
        assert_eq!(validate_logo_uri(None).unwrap(), None);
        assert_eq!(validate_logo_uri(Some(String::new())).unwrap(), None);
        assert_eq!(validate_logo_uri(Some("   ".to_owned())).unwrap(), None);
        assert_eq!(validate_client_uri(Some("\t".to_owned())).unwrap(), None);
    }

    #[test]
    fn https_uri_is_accepted_and_canonicalized() {
        assert_eq!(
            validate_logo_uri(Some(" https://cdn.example.com/logo.png ".to_owned())).unwrap(),
            Some("https://cdn.example.com/logo.png".to_owned())
        );
        assert_eq!(
            validate_client_uri(Some("https://app.example.com".to_owned())).unwrap(),
            Some("https://app.example.com/".to_owned())
        );
    }

    #[test]
    fn rejects_insecure_or_dangerous_uris() {
        for value in [
            "http://cdn.example.com/logo.png",
            "javascript:alert(1)",
            "data:image/png;base64,aaaa",
            "https://cdn.example.com/logo.png#x",
            "https://user:pass@cdn.example.com/logo.png",
            "https://cdn.example.com/*.png",
            "not a url",
        ] {
            assert_eq!(
                validate_logo_uri(Some(value.to_owned())).unwrap_err(),
                ClientRegistrationError::InvalidLogoUri,
                "{value}"
            );
            assert_eq!(
                validate_client_uri(Some(value.to_owned())).unwrap_err(),
                ClientRegistrationError::InvalidClientUri,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_overlong_uri() {
        let value = format!(
            "https://cdn.example.com/{}",
            "a".repeat(MAX_PRESENTATION_URI_LENGTH)
        );
        assert_eq!(
            validate_logo_uri(Some(value)).unwrap_err(),
            ClientRegistrationError::InvalidLogoUri
        );
    }
}
