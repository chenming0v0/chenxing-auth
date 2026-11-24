# Issues #733–#749 修复说明

## 用户流程

OAuth 授权确认页照常进入并完成普通授权。应用取得 OAuth AT 后，每次申请外部登录票都查询提供方最新账号状态；旧禁用快照不阻止再次查询。明确禁用时更新缓存并拒绝签票，恢复活跃时更新缓存并签票。网络、5xx 或协议失败保留旧快照，本次返回可重试错误。最终业务登录资格由外部服务检查。

## 修复对应

| Issue | 修复 |
| --- | --- |
| #733 | 新迁移固定审计函数的真实表 schema 和 `pg_temp` 查找位置，临时表不能参与归档。 |
| #734 | 持久化时复核最新非零计数；冲突返回 409，释放旧 challenge 后重新认证，不停用账号或凭据。 |
| #735 | GET/POST 一致处理不支持的响应模式、Request Object 和 Request URI；安全回跳，保留普通未知参数兼容。 |
| #736 | 提供方 metadata HTTP 移出写事务，锁内复核 revision 和身份限制。 |
| #737 | 手动同步与签票共用查询；活跃和禁用状态双向保存，门户会话失效不丢可信回复，查询序号防止旧回复覆盖。 |
| #738 | 替换旧应用前验证候选容器就绪，切换失败自动恢复原镜像并检查回滚结果。 |
| #739 | 目标版本只写临时配置，最终就绪后才提交 `.env`；失败保留旧版本锚点。 |
| #740 | 标签构建必须等待同一 SHA 的最新 `releases` push CI 成功；后续构建固定使用已验证 SHA。 |
| #741 | 587 使用强制 STARTTLS，其余端口保留 TLS 模式选择和证书校验。 |
| #742 | 强制 AUTH LOGIN 时只协商 LOGIN。 |
| #743 | 支持完整配置的免认证中继，保存时拒绝单边缺失凭据。 |
| #744 | 新增已记录失败计数；中断领取和数据库不确定结果不消耗死信预算。 |
| #745 | 首次未登录确认保留公开表单，不广播真实登出；真正登出和切账号继续清理账户状态。 |
| #746 | 变更期间同步阻止所有列表重试，变更开始与结束均作废旧 GET。 |
| #747 | 撤销成功或 404 后立即移除本地会话，后台刷新失败不恢复旧行。 |
| #748 | 所有锁到手后重新判断套餐，最终 INSERT 再按当前时间和配额准入。 |
| #749 | API 入口与路由按职责拆分，保持中间件顺序并更新路由契约扫描。 |

## 验证

子代理仅编写实现和回归文件、执行静态审阅，测试与编译由主代理统一执行。完成本地 1037 项 Rust 单元测试、前端相关回归、30 项部署/发布脚本回归，以及测试目标编译、OpenAPI、Action 引用、Compose 和迁移校验和检查。数据库集成、全量前端、Clippy、覆盖率门槛和依赖审计由 `dev` CI 执行。

新增迁移 0060、0061、0062 均加入内嵌迁移列表及校验清单；已发布迁移字节不变。升级不反向回滚数据库，旧版本与新账本不兼容时回滚检查会明确报错；候选就绪检查在替换旧容器之前完成。

## 源文件行数弱警告

本次变更没有超过 500 行的源文件。301–500 行文件如下：

| 文件 | 行数 |
| --- | ---: |
| `src/auth_factors/handlers/passkey.rs` | 331 |
| `src/auth_factors/service.rs` | 420 |
| `src/clients/repository_core.rs` | 473 |
| `src/clients/repository_idempotency.rs` | 339 |
| `src/db/embedded_migrations.rs` | 333 |
| `src/oauth/authorization_decision_use_case.rs` | 456 |
| `src/plans/repository.rs` | 416 |
| `src/resource_services/exchange.rs` | 328 |
| `src/resource_services/store/binding.rs` | 317 |
| `src/settings/service.rs` | 376 |
| `web/src/api-types.ts` | 435 |
| `web/src/api.ts` | 371 |
| `web/src/auth-state.tsx` | 307 |
| `web/src/pages/admin/settings/oauth-providers-panel.test.tsx` | 383 |
| `web/src/pages/console/profile-apps.tsx` | 359 |
