-- Owner 初始化需要写 users 的 identity 序列，但 0019 只给运行时角色授了
-- 序列的 USAGE, SELECT。setval() 要求序列的 UPDATE 权限，因此在角色分离部署
-- 下 bootstrap_owner 的 setval 必然报 "permission denied for sequence"，
-- 第一个 Owner 根本建不出来。单角色部署看不到这个洞，因为那时运行时角色就是
-- 序列 owner，隐含全部权限。
--
-- 只放开 users 的 identity 序列这一个对象：Owner 初始化要求 id 从 1 开始
-- （见 bootstrap_owner 与 tests/bootstrap_invariant.rs），这是唯一需要运行时
-- 写序列的路径。审计表的序列保持只读，append-only 边界不受影响。
DO $$
DECLARE
    users_id_sequence text := pg_get_serial_sequence('users', 'id');
BEGIN
    IF users_id_sequence IS NULL THEN
        RAISE EXCEPTION 'users.id has no owned sequence; cannot grant runtime setval';
    END IF;
    EXECUTE format('GRANT UPDATE ON SEQUENCE %s TO chenxing_runtime', users_id_sequence);
END
$$;
