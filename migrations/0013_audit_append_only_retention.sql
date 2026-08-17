-- Issue #159: make the audit boundary real instead of relying on module comments.
--
-- The application role currently owns migrations, normal audit writes, and the
-- maintenance command. REVOKE cannot distinguish those operations for this
-- deployment model, so the database boundary is enforced with triggers. The
-- archive function is the only application-supported exception for moving old
-- rows out of the hot table.
--
-- Rollback note: stop the audit-archive scheduler first. Before dropping this
-- migration, restore rows from audit_events_archive to audit_events with
-- `OVERRIDING SYSTEM VALUE`, then drop the triggers, function, indexes, and
-- archive table in reverse order. Never drop the archive table after rows have
-- been moved without restoring those rows first.

CREATE TABLE audit_events_archive (
    id BIGINT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_user_id BIGINT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX audit_events_archive_created_at_idx
    ON audit_events_archive (created_at DESC, id DESC);
CREATE INDEX audit_events_archive_action_idx
    ON audit_events_archive (action, created_at DESC, id DESC);
CREATE INDEX audit_events_archive_resource_idx
    ON audit_events_archive (resource_type, resource_id);
CREATE INDEX audit_events_archive_actor_user_idx
    ON audit_events_archive (actor_user_id, created_at DESC);

CREATE INDEX audit_events_action_idx
    ON audit_events (action, created_at DESC, id DESC);

-- The baseline used ON DELETE SET NULL here. PostgreSQL implements that
-- referential action as an UPDATE on audit_events, which would contradict the
-- append-only guarantee. An audit actor id is historical data, so it may refer
-- to a user that no longer exists; anonymous events remain NULL.
ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS audit_events_actor_user_id_fkey;

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The archive function sets this transaction-local marker immediately
    -- before its copy-then-delete statement. UPDATE and TRUNCATE never have a
    -- bypass, and the archive table never has a bypass.
    IF TG_TABLE_NAME = 'audit_events'
       AND TG_OP = 'DELETE'
       AND current_setting('chenxing.audit_events_archive', true) = 'on' THEN
        RETURN NULL;
    END IF;

    RAISE EXCEPTION 'audit event tables are append-only; % on %.% is not permitted',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER audit_events_append_only_trigger
BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_archive_append_only_trigger
BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events_archive
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE OR REPLACE FUNCTION archive_audit_events(
    p_retention_days INTEGER,
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    archived_count INTEGER;
BEGIN
    IF p_retention_days < 1 OR p_retention_days > 36500 THEN
        RAISE EXCEPTION 'audit retention must be between 1 and 36500 days'
            USING ERRCODE = '22023';
    END IF;
    IF p_batch_size < 1 OR p_batch_size > 10000 THEN
        RAISE EXCEPTION 'audit archive batch size must be between 1 and 10000'
            USING ERRCODE = '22023';
    END IF;

    -- One scheduler is recommended, but this also keeps concurrent invocations
    -- from selecting the same batch when an operator retries a job.
    PERFORM pg_advisory_xact_lock(hashtext('chenxing.audit_events.archive'));
    PERFORM set_config('chenxing.audit_events_archive', 'on', true);

    WITH candidates AS (
        SELECT id
        FROM audit_events
        WHERE created_at < CURRENT_TIMESTAMP - make_interval(days => p_retention_days)
        ORDER BY created_at, id
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    ), copied AS (
        INSERT INTO audit_events_archive
            (id, actor_type, actor_user_id, action, resource_type, resource_id,
             metadata, created_at)
        SELECT event.id, event.actor_type, event.actor_user_id, event.action,
               event.resource_type, event.resource_id, event.metadata, event.created_at
        FROM audit_events AS event
        JOIN candidates ON candidates.id = event.id
        ON CONFLICT (id) DO NOTHING
        RETURNING id
    )
    DELETE FROM audit_events AS event
    USING copied
    WHERE event.id = copied.id;

    GET DIAGNOSTICS archived_count = ROW_COUNT;
    PERFORM set_config('chenxing.audit_events_archive', 'off', true);
    RETURN archived_count;
END;
$$;

-- The owner (the current single application/migration role) retains implicit
-- EXECUTE. Other roles must be granted this maintenance capability explicitly.
REVOKE ALL ON FUNCTION archive_audit_events(INTEGER, INTEGER) FROM PUBLIC;

COMMENT ON TABLE audit_events_archive IS
    'Immutable audit events moved out of the hot table after the configured hot retention window';
COMMENT ON FUNCTION archive_audit_events(INTEGER, INTEGER) IS
    'Atomically copies old audit events to the immutable archive and removes only copied hot rows';
