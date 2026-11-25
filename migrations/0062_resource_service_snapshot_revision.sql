-- 查询序号与授权 generation 分开：刷新快照不能改变已签登录票的关联代数。
ALTER TABLE resource_service_bindings
    ADD COLUMN snapshot_revision BIGINT NOT NULL DEFAULT 0
    CHECK (snapshot_revision >= 0);
