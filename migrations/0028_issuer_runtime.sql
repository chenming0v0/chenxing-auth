ALTER TABLE app_settings
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT app_settings_generation_nonnegative CHECK (generation >= 0);

UPDATE app_settings
SET generation = 1
WHERE setting_key = 'app_issuer' AND setting_value IS NOT NULL;

CREATE OR REPLACE FUNCTION guard_app_issuer_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutated_key TEXT;
    relation_owner TEXT;
BEGIN
    mutated_key := CASE WHEN TG_OP = 'DELETE' THEN OLD.setting_key ELSE NEW.setting_key END;
    IF mutated_key <> 'app_issuer' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;

    SELECT pg_get_userbyid(relowner)
    INTO relation_owner
    FROM pg_class
    WHERE oid = TG_RELID;

    -- The dedicated SECURITY DEFINER function executes as the table owner. Runtime
    -- sessions cannot bypass this guard with direct INSERT/UPDATE/DELETE statements.
    IF current_user = relation_owner THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;

    RAISE EXCEPTION 'app_issuer may only be changed through set_app_issuer()'
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER app_issuer_controlled_write_trigger
BEFORE INSERT OR UPDATE OR DELETE ON app_settings
FOR EACH ROW
EXECUTE FUNCTION guard_app_issuer_mutation();

CREATE OR REPLACE FUNCTION set_app_issuer(
    p_value TEXT,
    p_expected_generation BIGINT
)
RETURNS TABLE (
    previous_value TEXT,
    setting_value TEXT,
    generation BIGINT,
    updated_at TIMESTAMPTZ,
    changed BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    current_value TEXT;
    current_generation BIGINT;
    next_generation BIGINT;
    changed_at TIMESTAMPTZ;
BEGIN
    IF p_value IS NULL OR btrim(p_value) = '' OR length(p_value) > 2048 THEN
        RAISE EXCEPTION 'issuer value is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_expected_generation < 0 THEN
        RAISE EXCEPTION 'issuer generation is invalid' USING ERRCODE = '22023';
    END IF;

    SELECT settings.setting_value, settings.generation
    INTO current_value, current_generation
    FROM app_settings AS settings
    WHERE settings.setting_key = 'app_issuer'
    FOR UPDATE;

    IF NOT FOUND THEN
        IF p_expected_generation <> 0 THEN
            RETURN;
        END IF;
        next_generation := 1;
        changed_at := NOW();
        INSERT INTO app_settings (setting_key, setting_value, updated_at, generation)
        VALUES ('app_issuer', p_value, changed_at, next_generation);
        PERFORM pg_notify('chenxing_issuer', next_generation::TEXT);
        RETURN QUERY SELECT NULL::TEXT, p_value, next_generation, changed_at, TRUE;
        RETURN;
    END IF;

    IF current_generation <> p_expected_generation THEN
        RETURN;
    END IF;
    IF current_value = p_value THEN
        RETURN QUERY
        SELECT current_value, current_value, current_generation,
               settings.updated_at, FALSE
        FROM app_settings AS settings
        WHERE settings.setting_key = 'app_issuer';
        RETURN;
    END IF;

    next_generation := current_generation + 1;
    changed_at := NOW();
    UPDATE app_settings AS settings
    SET setting_value = p_value,
        generation = next_generation,
        updated_at = changed_at
    WHERE settings.setting_key = 'app_issuer';
    PERFORM pg_notify('chenxing_issuer', next_generation::TEXT);
    RETURN QUERY SELECT current_value, p_value, next_generation, changed_at, TRUE;
END;
$$;

DO $$
DECLARE
    target_schema TEXT := current_schema();
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.set_app_issuer(TEXT, BIGINT)
             SECURITY DEFINER
             SET search_path = pg_catalog, %I',
        target_schema,
        target_schema
    );
    EXECUTE format(
        'REVOKE ALL ON FUNCTION %I.set_app_issuer(TEXT, BIGINT) FROM PUBLIC',
        target_schema
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION %I.set_app_issuer(TEXT, BIGINT) TO chenxing_runtime',
        target_schema
    );
END;
$$;

COMMENT ON FUNCTION set_app_issuer(TEXT, BIGINT) IS
    'CAS-controlled application issuer update; direct runtime table mutation is rejected';
