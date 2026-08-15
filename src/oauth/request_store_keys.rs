use super::AuthorizationRequestStore;

impl AuthorizationRequestStore {
    pub(super) fn request_prefix(&self) -> String {
        self.keyspace.prefix("chenxing:oauth:request:")
    }

    pub(super) fn key(&self, request_id: &str) -> String {
        format!("{}{request_id}", self.request_prefix())
    }

    pub(super) fn client_capacity_prefix(&self) -> String {
        self.keyspace.prefix("chenxing:oauth:pending:client:")
    }

    pub(super) fn client_capacity_key(&self, client_id: &str) -> String {
        format!("{}{client_id}", self.client_capacity_prefix())
    }

    pub(super) fn global_capacity_key(&self) -> String {
        self.keyspace.key("chenxing:oauth:pending:global")
    }

    pub(super) fn client_index_prefix(&self) -> String {
        self.keyspace
            .prefix("chenxing:oauth:pending:client-requests:")
    }

    pub(super) fn client_index_key(&self, client_id: &str) -> String {
        format!("{}{client_id}", self.client_index_prefix())
    }

    pub(super) fn global_index_key(&self) -> String {
        self.keyspace.key("chenxing:oauth:pending:index")
    }

    pub(super) fn global_expiry_key(&self) -> String {
        self.keyspace.key("chenxing:oauth:pending:expiry")
    }
}
