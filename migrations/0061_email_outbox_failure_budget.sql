-- 领取次数用于日志，失败预算只统计已成功落库的投递失败。
ALTER TABLE email_outbox
    ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0,
    ADD CONSTRAINT email_outbox_failed_attempts_check CHECK (failed_attempts >= 0);

-- 旧 attempts 混有中断领取，无法重建历史失败次数，不能直接复制。
-- 保留已有死信终态；其余记录最多继承 last_error 能证明的一次失败。
-- database_failure 代表投递结果未知，不计入投递失败预算。
UPDATE email_outbox
SET failed_attempts = CASE
    WHEN dead_lettered_at IS NOT NULL THEN 10
    WHEN last_error IS NOT NULL AND last_error <> 'database_failure' THEN 1
    ELSE 0
END
WHERE dead_lettered_at IS NOT NULL
   OR (last_error IS NOT NULL AND last_error <> 'database_failure');
