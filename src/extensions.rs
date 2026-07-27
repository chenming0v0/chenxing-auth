//! Isolated extension points for business platforms integrating with the
//! independent Chenxing authentication service.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BusinessExtensionClaim {
    pub namespace: String,
    pub name: String,
    pub value: serde_json::Value,
}

pub trait BusinessExtension: Send + Sync {
    fn extension_id(&self) -> &'static str;

    fn claims_for_user(
        &self,
        user_id: uuid::Uuid,
        requested_scopes: &[String],
    ) -> Vec<BusinessExtensionClaim>;
}

#[derive(Debug, Clone, Default)]
pub struct EmptyExtension;

impl BusinessExtension for EmptyExtension {
    fn extension_id(&self) -> &'static str {
        "empty"
    }

    fn claims_for_user(
        &self,
        _user_id: uuid::Uuid,
        _requested_scopes: &[String],
    ) -> Vec<BusinessExtensionClaim> {
        Vec::new()
    }
}
