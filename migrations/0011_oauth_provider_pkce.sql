-- 为外部 IdP provider 增加 PKCE 开关，默认开启。
--
-- **背景**（Issue #108）：
-- 本系统作为 OAuth 客户端访问外部 IdP 时，授权请求完全不带 `code_challenge`，
-- token 请求也不带 `code_verifier`。一旦授权码在传输链路、浏览器历史、Referer
-- 或日志中泄露，攻击者可直接向外部 IdP 的 token 端点重放该码。
--
-- 这与本项目对自己的 OAuth Client 强制 S256 PKCE 的策略自相矛盾：对外要求 PKCE，
-- 对内当客户端时却不用。RFC 9700 §2.1.1 要求所有授权码流程都使用 PKCE，
-- 不区分公开客户端和机密客户端（`client_secret` 只是部分补偿，不是替代品）。
--
-- **为什么需要开关而不是全局强制**：
-- 少数外部 IdP 尚未实现 RFC 7636，收到未知的 `code_challenge` 参数可能直接报错。
-- 开关做到 provider 粒度，让个别不兼容的 IdP 可以显式关闭，而不是为了兼容一个
-- IdP 就在全局放弃 PKCE。
--
-- **默认值 TRUE**：
-- 安全默认。存量 provider 自动获得 PKCE 保护，无需运维介入。若某个 IdP 因此
-- 失败，管理员可通过更新接口显式关闭；这是「默认安全、显式降级」而不是反过来。
--
-- **兼容性**：
-- 幂等操作：使用 `IF NOT EXISTS` 子句，允许在已执行该迁移的环境中重复运行。
-- 加列带常量默认值在 PostgreSQL 11+ 不重写全表，对线上无锁表风险。

ALTER TABLE oauth_providers
    ADD COLUMN IF NOT EXISTS pkce_enabled BOOLEAN NOT NULL DEFAULT TRUE;
