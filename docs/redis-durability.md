# Redis 凭据状态持久化与崩溃恢复

Redis 在本项目里不只是缓存。授权码与 Refresh Token 的部分状态是安全判定的权威事实，回滚一次已经确认的删除、轮换或撤销，就可能让单次凭据重新可用。

## 权威状态

| 流程 | 成功后的权威 Redis 状态 | 不允许回滚的原因 |
| --- | --- | --- |
| 授权码消费 | 授权码哈希键已由 CAS/Lua 原子删除；有关联配额时，待退条目在同一脚本中取消 | PostgreSQL 没有可替代的“已消费”副本；旧键复活会允许再次兑换 |
| Refresh Token 轮换 | 后继 token 主键和 client/grant/family 索引存在；前驱主键及旧索引成员消失；前驱的 `Consumed` tombstone 存在 | 前驱复活会破坏 rotation 的单次消费；墓碑丢失会把重放降级成未知 token |
| 重放或显式撤销 | 活跃 token 主键和索引成员消失；成员 tombstone 与 `family revoked` 墓志存在 | 墓志阻止飞行中的 rotation 把新成员写回已经死亡的 family |
| grant 撤销 | Redis 删除该 `(user_id, client_id)` 下的 token，并写 `ExplicitRevoke` tombstone 与 family 墓志；PostgreSQL consent 行同时是授权关系的权威事实 | Redis 负责立即销毁凭据，数据库负责阻止以后按已撤销授权继续兑换 |
| Session 撤销与用户 epoch | 活跃 Session Redis 投影删除；生产键 `revoked-epoch:<user_id>` 用户水位在同一原子变更中单调前进并带 TTL（崩溃脚本用 `session:revoked:epoch` 作为隔离标记） | 投影复活会重新接受已撤销会话；epoch 回退会让旧会话绕过撤销水位 |
| Client Secret 轮换 | PostgreSQL 的 `client_secret_version` 是最终签发与兑换栅栏；Redis token 删除是立即清理 | 即使 Redis 清理暂时失败，旧版本 token 仍被数据库版本拒绝 |

活跃 token 主键回答“当前是否可兑换”，`Consumed` tombstone 回答“是否发生了重放”，`ExplicitRevoke`/`FamilyRevoked` tombstone 与 family 墓志回答“该凭据或 family 是否已死亡”。这些键必须作为一个持久化安全状态集合恢复，不能只恢复活跃 token 而丢弃墓碑或撤销标记。

## RPO 与持久化策略

生产契约是：Redis 已经向应用确认成功的凭据状态变更，在 Redis 进程、容器或宿主机崩溃后使用同一持久卷恢复时，目标为 **RPO 0**。前提是底层文件系统和存储设备真实兑现 `fsync`，且没有丢失、替换或回滚命名卷。

`docker-compose.prod.yml` 与远程安装器生成的 Compose 使用以下策略：

- `appendonly yes`：以 AOF 保存写命令，不依赖定期 RDB 快照。
- `appendfsync always`：每次修改在确认给客户端前同步 AOF；Redis 默认的 `everysec` 会接受约 1 秒的数据丢失窗口，不符合凭据单次消费语义。
- `no-appendfsync-on-rewrite no`：AOF rewrite 期间仍执行同步，不能为了吞吐量临时放宽安全窗口。
- `aof-load-truncated no`：AOF 尾部截断或损坏时拒绝启动，不静默加载旧前缀。
- `save ""`：关闭周期 RDB 快照，避免运维误把较旧快照当成凭据状态恢复源；AOF rewrite 的 RDB preamble 仍由 `aof-use-rdb-preamble yes` 管理。
- `dir /data` 与 `appenddirname appendonlydir`：AOF 文件位于命名卷 `chenxing-redis:/data` 覆盖的 `/data/appendonlydir`。

客户端没有收到成功响应的在途命令结果仍然是不确定的：命令可能没有执行，也可能已经持久化但响应在崩溃中丢失。调用方必须按协议重试并接受“旧凭据已经失效”的结果，不能因为响应丢失而恢复旧状态。

`appendfsync always` 会增加每次 Redis 写操作的存储延迟和 IOPS，授权、token rotation、撤销、Session 与限流写入都会受到影响。生产容量规划必须以同步写延迟为基线；若改回 `everysec`，就等于明确接受最多约 1 秒的授权码或 Refresh Token 状态回滚，此配置不受项目安全契约支持。

## 备份与恢复

1. 同卷的进程或宿主机故障，保留 `chenxing-redis` 命名卷并直接重启 Redis。不得执行 `docker compose down -v`，也不得创建空卷覆盖原卷。
2. 计划备份前先停止应用写流量，确认 `INFO persistence` 中 `aof_enabled:1`、`aof_last_write_status:ok`，再对整个 `/data` 卷做一致性快照。备份必须记录 Redis 镜像版本、时间点和命名空间，并按认证凭据材料加密和限制访问。
3. **陈旧 Redis 备份不得直接恢复并接回生产流量。** 备份时间点之后发生的授权码消费、rotation、tombstone 和 revoke 会全部回滚，可能复活已经使用或撤销的凭据。当前系统没有覆盖所有授权码与 Refresh Token 的跨备份全局失效栅栏。
4. 卷丢失或只有陈旧备份时，安全默认是启动空 Redis，令所有未完成授权码、Refresh Token、Session 与短期流程失效，并要求用户重新登录/授权。可用性损失优先于凭据复活。
5. `aof-load-truncated no` 导致 Redis 拒绝启动时，不得改成 `yes` 强行加载。先保存故障卷用于分析；只有完整、同时间点的 AOF 副本可以原位恢复，否则按上一条使用空 Redis。

PostgreSQL 和 `KEY_DIRECTORY` 仍需独立备份。Redis 卷备份不能替代数据库、签名私钥或 Provider Secret 备份，也不能与不同时间点的 PostgreSQL 备份随意拼接。

## 故障后验证

恢复期间先保持应用停止，再检查 Redis：

```bash
docker compose --env-file .env -f docker-compose.prod.yml logs redis
docker compose --env-file .env -f docker-compose.prod.yml exec -T redis \
  redis-cli --raw CONFIG GET appendonly
docker compose --env-file .env -f docker-compose.prod.yml exec -T redis \
  redis-cli --raw CONFIG GET appendfsync
docker compose --env-file .env -f docker-compose.prod.yml exec -T redis \
  redis-cli --raw CONFIG GET aof-load-truncated
docker compose --env-file .env -f docker-compose.prod.yml exec -T redis \
  redis-cli --raw INFO persistence
```

必须确认 `appendonly=yes`、`appendfsync=always`、`aof-load-truncated=no`、`aof_enabled:1` 和 `aof_last_write_status:ok`，且日志没有 AOF 截断、校验失败或使用旧目录的提示。

`test_sh/redis_crash_recovery.sh` 会创建隔离容器和临时卷，写入授权码消费、Refresh Token rotation、`Consumed` tombstone、显式撤销 tombstone、family revoked 墓志，以及 Session 投影删除与 epoch 前进，随后立即发送 `SIGKILL` 并用同一卷恢复。恢复断言旧授权码、旧 token、已撤销 Session 投影均不存在，后继状态和最新 epoch 仍然存在。它只应用于 CI 或维护环境，不操作生产卷。

恢复上线前还应使用受控测试 Client 做一次端到端检查：消费一个授权码、完成一次 rotation、撤销一个独立 family，重启 Redis 后确认旧授权码和旧 Refresh Token 均返回 `invalid_grant`，后继 token 仍符合预期，已撤销 family 的所有成员仍不可用。测试值不得进入日志、工单或命令历史。
