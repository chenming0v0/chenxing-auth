use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    Approve,
    Deny,
}

pub fn parse_decision(value: &str) -> Option<ConsentDecision> {
    match value {
        "approve" => Some(ConsentDecision::Approve),
        "deny" => Some(ConsentDecision::Deny),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub request_id: String,
    pub decision: String,
    pub csrf_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthorization {
    pub request_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}
