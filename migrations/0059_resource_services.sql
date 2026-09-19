-- 账号门户提供方（Account Provider v1 消费方）改名为「资源服务」，并淘汰旧的
-- CLtermux 定制层（linked_accounts 表与 app_settings 里的 account_providers 注册表）。
--
-- 四张 0058 表与其索引/约束按 account_portal_ → resource_service_ 同规则改名；
-- 提供方表新增 scope 声明字段：scope 不再硬编码，由资源服务记录声明，管理员决定
-- 该 scope 是否向本站其他应用开放（scope_access）以及限定应用列表（allowed_client_ids）。
--
-- 这些表尚未上线、行数为零，因此 NOT NULL 列先带默认值加入再 DROP DEFAULT。

ALTER TABLE account_portal_providers RENAME TO resource_service_providers;
ALTER TABLE account_portal_bindings RENAME TO resource_service_bindings;
ALTER TABLE account_portal_operations RENAME TO resource_service_operations;
ALTER TABLE account_portal_revocation_outbox RENAME TO resource_service_revocation_outbox;

-- resource_service_providers 约束
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_pkey TO resource_service_providers_pkey;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_display_name_check TO resource_service_providers_display_name_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_issuer_check TO resource_service_providers_issuer_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_client_id_check TO resource_service_providers_client_id_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_secret_check TO resource_service_providers_secret_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_identifier_label_check TO resource_service_providers_identifier_label_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_secret_label_check TO resource_service_providers_secret_label_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_revision_check TO resource_service_providers_revision_check;
ALTER TABLE resource_service_providers
    RENAME CONSTRAINT account_portal_providers_issuer_key TO resource_service_providers_issuer_key;

-- resource_service_bindings 约束与索引
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_pkey TO resource_service_bindings_pkey;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_provider_id_fkey TO resource_service_bindings_provider_id_fkey;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_user_id_fkey TO resource_service_bindings_user_id_fkey;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_uid_check TO resource_service_bindings_uid_check;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_issuer_check TO resource_service_bindings_issuer_check;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_generation_check TO resource_service_bindings_generation_check;
ALTER TABLE resource_service_bindings
    RENAME CONSTRAINT account_portal_bindings_snapshot_size_check TO resource_service_bindings_snapshot_size_check;
ALTER INDEX account_portal_bindings_live_provider_user RENAME TO resource_service_bindings_live_provider_user;
ALTER INDEX account_portal_bindings_live_provider_uid RENAME TO resource_service_bindings_live_provider_uid;
ALTER INDEX account_portal_bindings_user_id_idx RENAME TO resource_service_bindings_user_id_idx;

-- resource_service_operations 约束与索引
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_pkey TO resource_service_operations_pkey;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_provider_id_fkey TO resource_service_operations_provider_id_fkey;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_user_id_fkey TO resource_service_operations_user_id_fkey;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_binding_fk TO resource_service_operations_binding_fk;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_type_check TO resource_service_operations_type_check;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_status_check TO resource_service_operations_status_check;
ALTER TABLE resource_service_operations
    RENAME CONSTRAINT account_portal_operations_fingerprint_check TO resource_service_operations_fingerprint_check;
ALTER INDEX account_portal_operations_binding_idx RENAME TO resource_service_operations_binding_idx;

-- resource_service_revocation_outbox 约束与索引
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_pkey TO resource_service_revocation_outbox_pkey;
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_provider_id_fkey TO resource_service_revocation_outbox_provider_id_fkey;
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_binding_id_fkey TO resource_service_revocation_outbox_binding_id_fkey;
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_user_id_fkey TO resource_service_revocation_outbox_user_id_fkey;
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_attempts_check TO resource_service_revocation_outbox_attempts_check;
ALTER TABLE resource_service_revocation_outbox
    RENAME CONSTRAINT account_portal_revocation_outbox_binding_key TO resource_service_revocation_outbox_binding_key;
ALTER INDEX account_portal_revocation_outbox_pending_idx RENAME TO resource_service_revocation_outbox_pending_idx;

-- scope 声明字段。slug / scope 全站唯一；scope 不得与 OIDC 保留 scope 冲突。
ALTER TABLE resource_service_providers
    ADD COLUMN slug TEXT NOT NULL DEFAULT '',
    ADD COLUMN scope TEXT NOT NULL DEFAULT '',
    ADD COLUMN scope_description TEXT NOT NULL DEFAULT '',
    ADD COLUMN scope_access TEXT NOT NULL DEFAULT 'restricted',
    ADD COLUMN allowed_client_ids TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE resource_service_providers
    ALTER COLUMN slug DROP DEFAULT,
    ALTER COLUMN scope DROP DEFAULT;

ALTER TABLE resource_service_providers
    ADD CONSTRAINT resource_service_providers_slug_check
        CHECK (slug ~ '^[a-z][a-z0-9_-]{0,63}$'),
    ADD CONSTRAINT resource_service_providers_scope_check
        CHECK (
            scope ~ '^[a-z][a-z0-9_.:-]{0,127}$'
            AND scope NOT IN ('openid', 'profile', 'email', 'offline_access')
        ),
    ADD CONSTRAINT resource_service_providers_scope_description_check
        CHECK (char_length(scope_description) <= 256),
    ADD CONSTRAINT resource_service_providers_scope_access_check
        CHECK (scope_access IN ('restricted', 'public')),
    ADD CONSTRAINT resource_service_providers_slug_key UNIQUE (slug),
    ADD CONSTRAINT resource_service_providers_scope_key UNIQUE (scope);

-- 旧 CLtermux 定制层：linked_accounts 表与 account_providers 设置注册表一并淘汰。
DROP TABLE IF EXISTS linked_accounts;
DELETE FROM app_settings WHERE setting_key = 'account_providers';
