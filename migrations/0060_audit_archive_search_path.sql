-- Issue #733：SECURITY DEFINER 归档只能读写迁移 schema 中的真实审计表。
-- PostgreSQL 在未显式列出 pg_temp 时会优先用临时表解析关系名，固定
-- search_path 仍不足以阻止运行角色用同名临时表伪造归档或截走真实记录。
-- CREATE OR REPLACE 保留原函数的身份、所有者和 EXECUTE 授权，不扩大表权限。
DO $migration$
DECLARE
    target_schema TEXT := pg_catalog.current_schema();
BEGIN
    EXECUTE pg_catalog.format($definition$
        CREATE OR REPLACE FUNCTION %1$I.archive_audit_events(
            p_retention_days INTEGER,
            p_batch_size INTEGER DEFAULT 1000
        )
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, %1$I, pg_temp
        AS $function$
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

            -- 沿用事务锁和先复制后删除的边界，只删除已复制成功的真实热表行。
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtext('chenxing.audit_events.archive')
            );
            PERFORM pg_catalog.set_config('chenxing.audit_events_archive', 'on', true);

            WITH candidates AS (
                SELECT id
                FROM %1$I.audit_events
                WHERE created_at < CURRENT_TIMESTAMP
                    - pg_catalog.make_interval(days => p_retention_days)
                ORDER BY created_at, id
                LIMIT p_batch_size
                FOR UPDATE SKIP LOCKED
            ), copied AS (
                INSERT INTO %1$I.audit_events_archive
                    (id, actor_type, actor_user_id, action, resource_type, resource_id,
                     metadata, created_at)
                SELECT event.id, event.actor_type, event.actor_user_id, event.action,
                       event.resource_type, event.resource_id, event.metadata, event.created_at
                FROM %1$I.audit_events AS event
                JOIN candidates ON candidates.id = event.id
                ON CONFLICT (id) DO NOTHING
                RETURNING id
            )
            DELETE FROM %1$I.audit_events AS event
            USING copied
            WHERE event.id = copied.id;

            GET DIAGNOSTICS archived_count = ROW_COUNT;
            PERFORM pg_catalog.set_config('chenxing.audit_events_archive', 'off', true);
            RETURN archived_count;
        END;
        $function$;
    $definition$, target_schema);
END;
$migration$;
