ALTER TABLE session_outbox
    DROP CONSTRAINT session_outbox_target_check;

ALTER TABLE session_outbox
    ADD CONSTRAINT session_outbox_target_check
        CHECK (
            (operation = 'revoke_user' AND user_id IS NOT NULL)
            OR (operation IN ('sync_session', 'revoke_session') AND token_hash IS NOT NULL)
            OR (session_id IS NULL AND user_id IS NULL AND token_hash IS NULL)
        );
