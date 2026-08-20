-- Issue #648: the runtime role may read archived audit history, but must not
-- INSERT into audit_events_archive. Migration 0019 revoked UPDATE/DELETE/TRUNCATE
-- on the archive while leaving INSERT, so a compromised runtime could forge
-- immutable security events or preinsert a colliding id and skip real archival
-- (`ON CONFLICT DO NOTHING` in archive_audit_events).
--
-- Archival still goes through the SECURITY DEFINER function from 0013/0019,
-- which runs as the table owner. SELECT stays granted so security-event APIs
-- can union archive history.
DO $$
DECLARE
    target_schema text := current_schema();
BEGIN
    EXECUTE format(
        'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I.audit_events_archive FROM chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I.audit_events_archive FROM PUBLIC',
        target_schema
    );
END
$$;
