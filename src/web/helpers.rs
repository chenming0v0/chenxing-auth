use crate::state::AppState;

pub async fn pending_request_exists(state: &AppState, request_id: &str) -> bool {
    state
        .authorization_requests
        .find(request_id)
        .await
        .ok()
        .flatten()
        .is_some()
}
