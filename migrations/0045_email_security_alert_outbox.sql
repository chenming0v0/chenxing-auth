-- Issue #678: make the email-change security alert durable and retryable.
-- Verification codes remain encrypted; security alerts store only their already
-- validated recipient address and a fixed message kind.
ALTER TABLE email_outbox
    ALTER COLUMN encrypted_code DROP NOT NULL,
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'verification_code',
    ADD COLUMN recipient TEXT;

ALTER TABLE email_outbox
    DROP CONSTRAINT email_outbox_code_check,
    DROP CONSTRAINT email_outbox_one_event_per_challenge,
    ADD CONSTRAINT email_outbox_kind_check CHECK (
        kind IN ('verification_code', 'email_change_security_alert')
    ),
    ADD CONSTRAINT email_outbox_payload_check CHECK (
        (kind = 'verification_code'
            AND encrypted_code IS NOT NULL
            AND recipient IS NULL)
        OR
        (kind = 'email_change_security_alert'
            AND encrypted_code IS NULL
            AND recipient IS NOT NULL
            AND octet_length(recipient) > 0)
    );

CREATE UNIQUE INDEX email_outbox_one_event_per_challenge
    ON email_outbox (challenge_id, kind);
