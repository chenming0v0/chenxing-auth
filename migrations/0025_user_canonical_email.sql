-- 为 users 增加独立的邮箱匹配列，并把唯一性约束落到它上面。
--
-- **背景**（Issue #302）：
-- 补丁前的邮箱规范化是 `email.trim().to_ascii_lowercase()`。`to_ascii_lowercase`
-- 只动 ASCII 字节，于是 `USER@ÉXAMPLE.COM` 落库成 `user@Éxample.com`，而同一个
-- 用户下次按常见小写形式输入 `user@éxample.com` 时匹配不上；`0001_initial.sql`
-- 上那条 `UNIQUE (email)` 比较的是这个未完全规范化的展示值，因此同一个邮箱的
-- 不同书写可以各自注册一个账号。应用层同时承担格式、归一化和唯一性，而数据库
-- 侧没有任何 canonical invariant——绕过应用层的写入完全不受约束。
--
-- **本迁移建立的不变量**：
-- `users.canonical_email` 是邮箱的匹配值，`users.email` 是展示值。匹配值由应用层
-- 的 `EmailAddress`（`src/users/email.rs`）唯一产出：域名走 UTS-46 IDNA 转 ASCII，
-- 本地部分只做 ASCII 大小写折叠。`UNIQUE (canonical_email)` 让"同一邮箱只能有一个
-- 账号"由数据库强制，绕过应用层的写入同样受约束。
--
-- **为什么两列而不是一列**：
-- 展示值要进邮件头、TOTP 标签和管理台列表，需要保留用户的原始拼写；匹配值要
-- 稳定、可比较、无等价歧义。把两种用途压进一列，就必须在"篡改用户输入"和
-- "唯一性有歧义"之间选一个。
--
-- ============================================================================
-- 回填策略：只回填 SQL 能自证的行，其余一律 fail loudly
-- ============================================================================
--
-- 回填值是 `lower(email)`。这个表达式**只在下述前提全部成立时**与应用层算出的
-- 匹配值逐字节相等：
--
--   1. `email` 是纯 ASCII。Postgres 的 `lower()` 依赖 locale，对非 ASCII 的折叠
--      规则与 Rust 的 `to_ascii_lowercase()`（只动 ASCII 字节）不同；而域名侧
--      应用层走的是 IDNA，与 `lower()` 更是两回事。
--   2. 结构合法：恰好一个 `@`，两侧非空，无空白与控制字符，总长 ≤ 254。
--   3. 域名是 LDH + 下划线形态、至少两个标签、每个标签 1..=63 字节、整体 ≤ 253。
--      这是 `DnsLength::Verify` 的要求，也是纯 ASCII 域名下 IDNA 转换退化为
--      恒等映射（外加小写）的条件。
--
-- 本判据**故意比应用层更严**。UTS-46 在 `UseSTD3ASCIIRules=false` 下还会放行
-- 一些冷门 ASCII 符号（`$`、`&`、`!` 等），SQL 无法在不重实现 UTS-46 的前提下
-- 证明这些行的转换结果，因此宁可交给人看，也不猜。判据的方向只有一个：
-- **能证明的才自动回填，证不出来的一律报错**。
--
-- 已知残留风险：`xn--` 标签的 Punycode 有效性无法在 SQL 里验证（需要真正解码 +
-- UTS-46 复检）。本迁移只校验它的字符集前提（`xn--` 后非空、ASCII 字母数字或
-- 连字符、不以连字符结尾），通过的行按 `lower(email)` 回填。之所以不把全部
-- `xn--` 行都拦下来交人工处理，是因为那样的行**没有可行的人工修复路径**：
-- 改成等价的 Unicode 形态会立刻违反第 1 条（非纯 ASCII），操作员会陷入死循环。
-- 字符集前提通过但解码失败的地址，本身就是一个无效的 IDNA 域名，在补丁前也
-- 只是"能存进库"而不是"真的能收信"。
--
-- ============================================================================
-- 操作员手册：迁移报错了怎么办
-- ============================================================================
--
-- 迁移在两种情况下会抛异常并整体回滚（sqlx 在事务内执行本迁移）：
--
-- **A. 存在无法回填的行**（异常信息带 user id 列表）
--    对每个 id 人工判断并改写 `users.email`，然后重跑迁移：
--    - 非 ASCII 域名（例如 `user@Éxample.com`）：改成等价的 Punycode 形态。
--      `SELECT` 出来的地址可以用任意 IDNA 工具转换，例如
--      `python3 -c "print('éxample.com'.encode('idna').decode())"`。
--    - 非 ASCII 本地部分：确认该账号真实存在且邮箱可达，再决定改写或删除。
--      本迁移刻意不替你猜非 ASCII 本地部分的等价关系。
--    - 结构损坏（多个 `@`、含空格、域名无点等）：这类行不是合法邮箱，
--      联系账号所有人确认后改写或删除。
--
-- **B. 存在 canonical 冲突**（异常信息带 canonical 值与 user id 列表）
--    说明补丁前已经有两个账号指向同一个邮箱。本迁移**不会**替你合并：合并涉及
--    会话、授权、订阅和审计归属，是业务决策而不是数据清洗。人工决定保留哪个
--    账号、如何迁移其数据，处理完再重跑迁移。
--
-- ============================================================================
-- 回滚
-- ============================================================================
--
--   ALTER TABLE users DROP CONSTRAINT users_canonical_email_key;
--   ALTER TABLE users DROP COLUMN canonical_email;
--
-- 不需要单独 DROP INDEX：唯一约束自带的索引随约束一起消失，登录查询
-- （`WHERE canonical_email = $1`）走的就是它，本迁移不再额外建索引。
--
-- 回滚不丢展示值（`email` 列未被本迁移改写），但会丢掉数据库级的 canonical
-- 唯一性；回滚后必须同时回滚应用版本，否则写路径会向不存在的列插值。

-- 幂等：允许在已执行过本迁移的环境中重复运行。
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS canonical_email TEXT;

-- 回填。只写 NULL 行，已有值不动。
UPDATE users
SET canonical_email = lower(email)
WHERE canonical_email IS NULL
  -- 纯 ASCII：UTF-8 下"字节数 = 字符数"等价于全部码点都是单字节。
  AND octet_length(email) = length(email)
  AND length(email) <= 254
  AND email !~ '[[:space:][:cntrl:]]'
  -- 恰好一个 @，两侧非空。
  AND email ~ '^[^@]+@[^@]+$'
  -- 域名：至少两个标签，每标签 1..=63 个 LDH/下划线字符，整体 ≤ 253。
  AND lower(split_part(email, '@', 2)) ~ '^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})+$'
  AND length(split_part(email, '@', 2)) <= 253
  -- `xn--` 标签的字符集前提（见文件头的残留风险说明）。
  AND NOT EXISTS (
      SELECT 1
      FROM unnest(string_to_array(lower(split_part(email, '@', 2)), '.')) AS label
      WHERE label LIKE 'xn--%'
        AND (
            substring(label FROM 5) = ''
            OR substring(label FROM 5) !~ '^[a-z0-9-]+$'
            OR substring(label FROM 5) LIKE '%-'
        )
  );

-- A. 无法回填的行：报错并列出 id，不静默留 NULL、也不猜一个值。
DO $$
DECLARE
    offending TEXT;
    offending_count BIGINT;
BEGIN
    SELECT count(*), string_agg(id::text, ', ' ORDER BY id)
    INTO offending_count, offending
    FROM users
    WHERE canonical_email IS NULL;

    IF offending_count > 0 THEN
        RAISE EXCEPTION
            'cannot derive canonical_email for % user row(s): id in (%). These addresses are not provably canonicalizable in SQL (non-ASCII, malformed, or an unsupported domain shape). Fix users.email for each id and re-run this migration; see the migration header for the procedure. This migration refuses to guess a canonical value.',
            offending_count, offending;
    END IF;
END
$$;

-- B. canonical 冲突：报错并列出冲突组，不静默合并账号。
DO $$
DECLARE
    conflicts TEXT;
    conflict_count BIGINT;
BEGIN
    SELECT count(*), string_agg(summary, '; ' ORDER BY summary)
    INTO conflict_count, conflicts
    FROM (
        SELECT canonical_email || ' -> id in (' || string_agg(id::text, ', ' ORDER BY id) || ')'
                   AS summary
        FROM users
        GROUP BY canonical_email
        HAVING count(*) > 1
    ) AS grouped;

    IF conflict_count > 0 THEN
        RAISE EXCEPTION
            'found % canonical email conflict group(s): %. Two or more existing accounts resolve to the same mailbox. Merging them affects sessions, consents, plans and audit attribution, so this migration will not do it silently: decide which account survives, migrate its data, then re-run.',
            conflict_count, conflicts;
    END IF;
END
$$;

ALTER TABLE users
    ALTER COLUMN canonical_email SET NOT NULL;

-- 命名约束而不是让 Postgres 生成名字：应用层按约束名把唯一冲突翻成
-- `email_already_registered`（见 `src/admin/user_creation.rs`），名字是契约。
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_canonical_email_key'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_canonical_email_key UNIQUE (canonical_email);
    END IF;
END
$$;
