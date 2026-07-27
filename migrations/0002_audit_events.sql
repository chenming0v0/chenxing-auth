CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at DESC);
CREATE INDEX audit_events_resource_idx ON audit_events (resource_type, resource_id);
