-- Issue #572: fence every outbox lease with a monotonically increasing generation
-- and an unpredictable token. A worker whose lease expired must not be able to
-- complete or reschedule a claim that has since been given to another worker.
ALTER TABLE session_outbox
    ADD COLUMN claim_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN claim_token TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN session_outbox.claim_generation IS
    'Monotonically increasing lease generation; completion and retry updates must match it';
COMMENT ON COLUMN session_outbox.claim_token IS
    'Opaque per-claim lease token; stale workers cannot mutate a re-claimed row';
