-- Snapshot columns for external identities (Issue #706).
-- Values are captured from provider userinfo claims at bind time. subject_hint
-- is a redacted summary produced by the application, never the raw subject.
-- extensions holds persisted extension entries; runtime-computed entries are
-- appended at read time and never written back.
ALTER TABLE oauth_external_identities
    ADD COLUMN IF NOT EXISTS account_name TEXT,
    ADD COLUMN IF NOT EXISTS avatar_url TEXT,
    ADD COLUMN IF NOT EXISTS provider_icon TEXT,
    ADD COLUMN IF NOT EXISTS subject_hint TEXT,
    ADD COLUMN IF NOT EXISTS account_status TEXT,
    ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sync_status TEXT,
    ADD COLUMN IF NOT EXISTS sync_error TEXT,
    ADD COLUMN IF NOT EXISTS extensions JSONB NOT NULL DEFAULT '[]'::jsonb;