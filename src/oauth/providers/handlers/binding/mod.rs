mod identity;
mod start;

pub use identity::{list_linked_identities, unlink_external_identity};
pub use start::{BindingCallbackQuery, external_binding_callback, start_external_binding};

use crate::{error, sessions::cookies, state::AppState};
use axum::response::Response;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};

pub(super) const BINDING_PURPOSE: &str = "binding";

pub(super) fn binding_error(
    state: &AppState,
    state_value: &str,
    code: &'static str,
    message: &'static str,
) -> Response {
    let mut response =
        if code.ends_with("conflict") || code.contains("owned") || code.contains("already") {
            error::conflict(code, message)
        } else {
            error::bad_request(code, message)
        };
    if let Err(error_value) = cookies::append_clear_external_state_cookie(
        response.headers_mut(),
        state_value,
        state.config.cookie_secure,
    ) {
        tracing::error!(error = %error_value, "failed to clear external identity binding state cookie");
        return error::internal();
    }
    response
}

pub(super) fn random_state() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn binding_callback_path(slug: &str) -> String {
    format!("/auth/external/{slug}/bind/callback")
}
