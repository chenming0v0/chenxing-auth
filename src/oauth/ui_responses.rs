use serde::Serialize;
use std::fmt;

#[derive(Serialize)]
pub(super) struct PendingRequestResponse {
    pub(super) request_id: String,
    pub(super) client_id: String,
    pub(super) client_name: String,
    pub(super) redirect_host: String,
    pub(super) scopes: Vec<String>,
    pub(super) expires_in: u64,
    pub(super) logo_uri: Option<String>,
    pub(super) client_uri: Option<String>,
}

impl fmt::Debug for PendingRequestResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRequestResponse")
            .field("request_id", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("redirect_host", &self.redirect_host)
            .field("scopes", &self.scopes)
            .field("expires_in", &self.expires_in)
            .field("logo_uri", &self.logo_uri)
            .field("client_uri", &self.client_uri)
            .finish()
    }
}

#[derive(Serialize)]
pub(super) struct DecisionResponse {
    pub(super) decision: &'static str,
    pub(super) redirect_to: String,
}

impl fmt::Debug for DecisionResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionResponse")
            .field("decision", &self.decision)
            .field("redirect_to", &"<redacted>")
            .finish()
    }
}
