CREATE INDEX users_admin_query_order_idx ON users (created_at DESC, id DESC);
CREATE INDEX users_admin_query_status_idx ON users (status, created_at DESC, id DESC);
CREATE INDEX oauth_clients_admin_query_order_idx
    ON oauth_clients (created_at DESC, id DESC);
CREATE INDEX oauth_clients_admin_query_status_idx
    ON oauth_clients (status, created_at DESC, id DESC);
