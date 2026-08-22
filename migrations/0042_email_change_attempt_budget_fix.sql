ALTER TABLE user_email_change_challenges
    DROP CONSTRAINT user_email_change_attempts_bounded,
    ADD CONSTRAINT user_email_change_attempts_bounded
    CHECK (
        failed_attempts <= 5
        AND in_flight_attempts <= 5
        AND cardinality(active_attempt_ids) <= 5
        AND in_flight_attempts = cardinality(active_attempt_ids)
    );
