ALTER TABLE user_email_change_challenges
    ADD COLUMN failed_attempts BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN in_flight_attempts BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN active_attempt_ids UUID[] NOT NULL DEFAULT '{}'::UUID[];

ALTER TABLE user_email_change_challenges
    ADD CONSTRAINT user_email_change_attempts_nonnegative
    CHECK (failed_attempts >= 0 AND in_flight_attempts >= 0);

ALTER TABLE user_email_change_challenges
    ADD CONSTRAINT user_email_change_attempts_bounded
    CHECK (
        failed_attempts <= 5
        AND in_flight_attempts <= 5
        AND failed_attempts + in_flight_attempts <= 5
        AND cardinality(active_attempt_ids) <= 5
        AND in_flight_attempts = cardinality(active_attempt_ids)
    );

-- Migration 0032 changed future-table defaults to SELECT-only for the runtime
-- role. This table was created by 0034 without an explicit DML grant, so repair
-- the permission boundary while adding the counters used by the live path.
GRANT SELECT, INSERT, UPDATE ON TABLE user_email_change_challenges TO chenxing_runtime;
