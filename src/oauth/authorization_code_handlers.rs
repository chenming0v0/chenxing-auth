use axum::response::{IntoResponse, Redirect, Response};

use super::{
    consent::PendingAuthorization,
    handlers::{
        AuthorizationCodeIssue, authorization_quota_redirect, issue_authorization_code_result,
    },
};
use crate::{oauth::authorization::ValidatedAuthorizationRequest, state::AppState};

pub async fn issue_authorization_code(
    state: &AppState,
    user_id: String,
    validated: ValidatedAuthorizationRequest,
) -> Response {
    let pending = PendingAuthorization {
        request_id: uuid::Uuid::new_v4().to_string(),
        client_id: validated.client_id.clone(),
        redirect_uri: validated.redirect_uri.clone(),
        scope: validated.scopes.join(" "),
        state: validated.state.clone(),
        nonce: validated.nonce.clone(),
        code_challenge: validated.code_challenge.clone(),
        code_challenge_method: "S256".to_owned(),
        session_id: None,
    };
    match issue_authorization_code_result(state, user_id, validated).await {
        Ok(AuthorizationCodeIssue::Redirect(redirect)) => Redirect::to(&redirect).into_response(),
        Ok(AuthorizationCodeIssue::QuotaExceeded) => authorization_quota_redirect(&pending),
        Err(response) => response,
    }
}
