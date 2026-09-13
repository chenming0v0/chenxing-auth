# DB 计时基线与模板生命周期（issue #710）

目标：在把 schema 夹具切换成模板克隆时，先量出真实成本再逐步落地。这里记录
各阶段、当前配置、JSONL 契约和限制。**CI 证据与数字见
[`test_sh/db_timing_results.md`](./db_timing_results.md)**，本页不复述具体数值。

## 阶段

- **STAGE 0（schema 基线）**：测量 schema 夹具成本。CI run
  [34734563113](https://github.com/chenming0v0/chenxing-auth/actions/runs/34734563113)
  （SHA `ff63326`）全绿：1876 用例通过；JSONL 983 行（481 fixture + 502
  migration）；五个 fixture 相位里 `fixture.migrate` 占 87.56%。
- **STAGE 1（模板基础设施，已完成）**：模板生命周期 + JUnit 关联落地。CI run
  [34739022956](https://github.com/chenming0v0/chenxing-auth/actions/runs/34739022956)
  （SHA `8914118`）全绿：1907 用例通过、覆盖率 81.70%、两个 job 的
  prepare/cleanup 都成功；wrapper 层 `template_fixture=0`、
  `template_prepare_ms=1250.329`。该 run 也提供了两个候选用例的 schema 基线（见
  结果页）。
- **STAGE 2（试点切换，已完成）**：只把两个具名 repository 用例切到模板克隆，
  **其余所有用例保持旧 schema 路径**。CI run
  [34742275829](https://github.com/chenming0v0/chenxing-auth/actions/runs/34742275829)
  （SHA `3ba5fba`）全绿：1908 用例通过、覆盖率 81.73%、两个 job prepare/cleanup
  成功、`template_fixture=2`。失败尝试与修正见结果页。
- **Phase 3 第一批（gate 已通过、已验证）**：23 用例审计通过，初始实现见 `13be5e7`
  （run [34748274304](https://github.com/chenming0v0/chenxing-auth/actions/runs/34748274304)，
  quality 全绿但 coverage 1 用例失败并中止，gate 当时未过）。代码排查随后定位到确定的
  共享 Redis 退款队列测试隔离缺陷；修复后 CI run
  [34750664243](https://github.com/chenming0v0/chenxing-auth/actions/runs/34750664243)
  （SHA `1c83587`）**三个 job 全绿**：两个 job 都 **1909/1909 passed, 0 failed,
  0 skipped**、覆盖率 **81.76%**、prepare/cleanup 都成功（各 25 clones + 1 template）。
  失败的 `13be5e7` 历史保留在结果页。
- **Phase 3 第二批（gate 已通过、已验证；planned scope 完成）**：候选审计 SAFE——
  `factors_repository`8 + `passkey_cas`3 共 11 个纯 PG 用例，无 Redis/AppState/全局
  worker/DDL，保留 max8；实现只把这两个私有 `database()` 的 callee 换成显式 template
  API，测试体不变。CI run
  [34752963270](https://github.com/chenming0v0/chenxing-auth/actions/runs/34752963270)
  （SHA `0f3ad2a`）**三个 job 全绿**：两个 job 都 **1909/1909 passed, 0 failed,
  0 skipped**、覆盖率 **81.75%**、prepare/cleanup 成功（各 36 clones + 1 template）、
  11 个 auth 候选在两个 job 都 PASS。实测计数：template **36**、schema **445**、
  migration **466**、prepare **1**、总记录 **948**。这 11 个 opt-in 让 `auth` 目标也
  需要先 prepare 模板（或在过滤掉它们时跳过）。

## 模板试点范围（stage 2）

`tests/storage/integration/repository.rs` 中只有这两个用例显式 opt-in 模板克隆：

- `integration::repository::postgres_repositories_round_trip_users_and_clients`
- `integration::repository::postgres_transaction_user_insert_and_missing_client_paths_work`

其余用例一律走旧 schema 路径。`--junit` 关联的就是这两个 identity，用于在切换
前后对比同一用例。

## 模板试点范围（phase 3 第一批，已实现）

历史事实要分清：**stage 2 只切了上面那两个** repository 用例；phase 3 第一批是
在此基础上**再新增 23 个** `plans::` 用例，不是替换或改写 stage 2 的结论。

- 来源：`tests/support/plans.rs` 新增显式 helper `test_state_from_template`，
  由以下 7 个文件里的 23 个 fixture 调用（逐文件计数）：`authorization_quota`3、
  `default_plan`5、`entitlements`3、`plan_admin`5、`plan_boundaries`2、
  `plan_quota`3、`qps_limit`2。`binary_name`/label 仍是 `plans`。
- 根 `db_isolation` 默认不变：仍是 schema 路径；模板是**按文件显式 helper 调用**，
  不做全局默认切换，也没有自动回退。`wallet` 的 15 个 fixture 保持 schema，不动。
- **初始切换（`13be5e7`）**：只把 fixture 获取方式换成 `test_state_from_template()`，
  测试断言体不变，原有 quota 断言与 limit 全部保留。
- **后续 Redis 修复（已由 `1c83587` 全量 CI 验证）**：代码排查定位到一个确定的共享 Redis
  退款队列测试
  隔离缺陷——worker 会扫描 keyspace 级队列，可能退还其它测试的 reservation，即使
  Client ID 唯一。修复不是原样回退调用点，而是有意改动测试注入 wiring：
  `test_state_from_template` 为本次测试签发新的 `plans-<uuid>` `RedisKeyspace`，
  `finish_plan_env` 在 `AppState` 之前写入 `config.redis_keyspace`；schema 路径的
  `test_state`/`test_state_with_max_connections` 仍传 `RedisKeyspace::default`（legacy）
  不变，`wallet` 15 个保持不动。`authorization_quota.rs` 的故障注入用同一 keyspace、
  同一时钟，并把健康的 `AuthorizationCodeStore` 保存后恢复，另加两个早期断言要求
  模板 fixture 配置非 legacy。新增确定性回归
  `tests/storage/redis/refund_namespace.rs::refund_queue_is_shared_across_client_ids_within_a_keyspace`。
  **未削弱任何 quota 断言/limit**。测试证明的是命名空间边界这一机制，不是历史的精确
  交织；也不声称生产 quota bug。
- 该修复已在 `1c83587` 全量 CI 通过（1909/1909、81.76%、cleanup 无残留）。

## 候选用例基线

切换前（旧 schema 路径）与切换后（v2 包裹计时）的逐用例数字、口径差异和合计，
见 [`test_sh/db_timing_results.md`](./db_timing_results.md)。要点：STAGE 1 的
`fixture_ms` 是 v1 五阶段之和的估计，STAGE 2 是 v2 `fixture_total_ms`，
两者口径不同，不能当同口径对比；也别用两个用例推断整套测试的加速比。

## 模板命名空间（shell / CI / 示例）

模板生命周期必须显式提供三个变量，**绝不回退到 `DATABASE_URL`**：

- `MIGRATION_DATABASE_URL`：跑迁移的 owner 连接。
- `CHENXING_TEST_TEMPLATE_DATABASE`：模板库全名。
- `CHENXING_TEST_DATABASE_PREFIX`：克隆库前缀。

命名规则（由示例/库校验，shell 只检查变量存在）：

- `prefix = ctest_<token>_`，总长 12..=36 字节；token 以 `[a-z0-9]` 开头和结尾，
  内部允许 `[a-z0-9_]`；不做任何归一化。
- 模板库名 **精确等于** `prefix + "template"`。
- 克隆库名格式为 `prefix + <16 位小写 hex> + "_" + <正数 canonical u32 PID>`。

CI 两个 job 用各自独立的命名空间（job 级 env），互不覆盖：

- quality：`ctest_${{ github.run_id }}_${{ github.run_attempt }}_quality_`
- coverage：`ctest_${{ github.run_id }}_${{ github.run_attempt }}_coverage_`

模板库与克隆库都是测试基础设施，只承载一次性测试 schema。它们**不是安全边界**：
模板按当前数据库 owner 的权限运行，是“只读的运维便利”，不要把它当成提权隔离
或超级用户防护。

环境变量优先级（`test_sh/test_database.sh`）：

- 调用方已导出的变量优先。只有**未设置**的变量才会用 `dev-env.sh` 的
  `chenxing_env_value` 从 `.env` 读单个键（绝不 `source .env`）。
- 显式设为**空串**仍算“已设置”，不会被 `.env` 覆盖，而是走到缺参失败。
- `DATABASE_URL` 是**可选**变量：存在就一并加载，供示例的源库保护逻辑使用；
  不存在也不要求，绝不作为三个必需变量的回退来源。

## 用法

前置：本机已有可用的 PostgreSQL / Redis 服务，以及对应的 owner 连接（见
`docker-compose.yml` 与 `.env.example`，这里不写任何口令）。**`storage` 与 `auth`
两个测试目标都包含显式 opt-in 模板克隆用例**（storage 的 plans 用例 + auth 的
`factors_repository`/`passkey_cas` 11 个），所以跑这两个目标前都必须先建好模板，
不能直接单跑；若只想跑非模板用例，需要显式过滤掉它们。模板相关变量只在命令内联
提供，不 `export`、不写进仓库。

一次性冒烟（这段只演示顺序，不在这里执行）：先 prepare，再跑 storage，最后用
`EXIT` trap 保证 cleanup 一定会跑；trap 保留原命令的退出码，cleanup 失败也把整条
命令判为失败。前缀用进程唯一的 `${BASHPID}` 派生、模板名由前缀推导，避免本地并发
运行时互相清理对方的命名空间；计时路径用一次性临时文件，避免多次运行混行。

```bash
#!/usr/bin/env bash
set -euo pipefail

# 前置：显式给出 owner 连接（占位符，绝不回退到 DATABASE_URL）。
owner_url="postgres://owner:REPLACE_ME@127.0.0.1:5432/chenxing_auth"
# 进程唯一前缀，避免并发本地运行共用同一命名空间；模板名必须等于 prefix + "template"。
prefix="ctest_local_${BASHPID}_"     # ctest_<token>_，12..=36 字节
template_db="${prefix}template"
tmp="$(mktemp -d)"
timing="$tmp/db-timing.jsonl"

# EXIT trap：先保留退出码，再 cleanup；cleanup 失败则整条命令失败。
trap 's=$?; \
  MIGRATION_DATABASE_URL="$owner_url" \
  CHENXING_TEST_TEMPLATE_DATABASE="$template_db" \
  CHENXING_TEST_DATABASE_PREFIX="$prefix" \
  ./test_sh/test_database.sh cleanup || s=1; \
  exit "$s"' EXIT

# 1) 先建模板（prepare 也写 prepare 计时行）。
CHENXING_TEST_DB_TIMING_FILE="$timing" \
MIGRATION_DATABASE_URL="$owner_url" \
CHENXING_TEST_TEMPLATE_DATABASE="$template_db" \
CHENXING_TEST_DATABASE_PREFIX="$prefix" \
  ./test_sh/test_database.sh prepare

# 2) 再跑 storage（含 opt-in 模板用例，消费上一步的模板）。
CHENXING_TEST_DB_TIMING_FILE="$timing" \
MIGRATION_DATABASE_URL="$owner_url" \
CHENXING_TEST_TEMPLATE_DATABASE="$template_db" \
CHENXING_TEST_DATABASE_PREFIX="$prefix" \
  ./test_sh/test.sh --test storage

# 3) 读同一份 JSONL；本地没有 nextest JUnit 时不加 --junit。
python3 test_sh/db_timing_report.py "$timing"
```

`--full`、`--gate`、`--coverage` 属编排者全量模式，默认只在 CI 失败需要本地
复现时才经授权运行，不作为本地默认示例。这里也不提供任何自动回退：缺变量就是
硬失败，`MIGRATION_DATABASE_URL` 不会回退到 `DATABASE_URL`。

报告器只读文件、不连数据库、不编译任何东西：

```
python3 test_sh/db_timing_report.py PATH [--junit target/nextest/default/junit.xml]
```

`--junit` 只关联两个固定候选用例（模板试点选定，见上）：`integration::repository::
postgres_repositories_round_trip_users_and_clients` 和 `integration::
repository::postgres_transaction_user_insert_and_missing_client_paths_work`。
JUnit 侧只认 nextest 0.9.143 的精确 classname `chenxing-auth::storage`（没有
裸 `storage` 别名），testcase `name` 必须精确等于 identity；timing 侧要求唯一
fixture 行、固定 binary 标签 `integration_storage`、`outcome=ok`。缺失、重复、
错误 binary、error fixture、失败/skip/flaky/rerun 都让对比失败；`time` 换算成
毫秒后必须仍是有限值。报告标题与分组保持 phase-neutral：模式由发出的行
（`version`/`event`/`database_mode`）推断，不按配置假设；每行打印的 basis 标明
该用例当前是 v1 schema 估计还是 v2 `fixture_total_ms`。
`body_residual_ms = test_elapsed_ms - fixture_ms` 含测试体、运行时开销和诊断写入，
不是纯 body；对 JUnit 3 位小数的四舍五入容忍 0.5 ms，更负则失败。

## CI 接线

quality job：工具装好后先 `Prepare template database`（也写 timing JSONL），再
`Run Rust tests in parallel`（同一 JSONL），随后无条件 `Cleanup template database`
（失败即让 job 失败），再跑报告（prepare 或 test 任一到达就执行）。报告只在
test 步骤**未跳过**时才追加 `--junit target/nextest/default/junit.xml`：tests 被
跳过时（例如 prepare 失败）省略该参数，让 JSONL 里的 error `template_prepare`
行照常渲染，而不是把一次 prepare 失败级联成第二个更含糊的红步；tests 真跑过时
`--junit` 仍是强制项，缺失或截断的 JUnit 依旧 fail-closed。报告为空时不写
step summary 的空代码块。最后无条件上传 `db-timing-diagnostics`（报告文本 +
原始 JSONL + JUnit）。`coverage` job 同样 prepare/cleanup，但**不注入 timing
变量**、不产计时数据，覆盖率门槛 `--fail-under-lines 75` 与 `rust-coverage`
工件不变。

nextest 只在现有 default profile 增加 JUnit 输出（`[profile.default.junit]`），
不新建 profile、不改并发/override/retry。

## JSONL 契约

每一行一个 JSON 对象。两代 schema 各自独立校验，v1 旧产物必须原样可解析。

v1（`database_mode="schema"`），元数据键：
`version, event, binary_name, test_identity, pid, database_mode, outcome, phases_ms`

- `fixture`：成功时恰好有 `bootstrap_connection`、`drop_create_schema`、
  `pool_connect`、`migrate`、`sequence_reset`；失败时允许子集。固定 ID 用例跳过
  `sequence_reset` 记 0。重复调用不去重。
- `migration`：成功时恰好有 `migration_lock_wait_ms` 和 `migration_apply_ms`；
  失败时可缺 lock（连接获取失败）或 apply（未执行到），apply 存在则 lock 必存在。

v2（`database_mode="template"`），元数据键同 v1，模板 fixture 额外带顶层
`fixture_total_ms`：

- `fixture`：成功时恰好有 `bootstrap_connection`、`database_clone_ms`、
  `pool_connect`、`sequence_reset`；失败时允许子集。`fixture_total_ms` 是配置解析
  前就开始的包裹计时（有限、非负）。
- `template_prepare`：成功时恰好有 `template_prepare_ms`，**没有**
  `fixture_total_ms`；失败时允许子集甚至为空。

`template_prepare` 的整体耗时已经包含内部 `db::migrate`，所以 prepare 期间用
task-local 作用域 suppress 掉嵌套的 migration 诊断事件（不改迁移语义、错误优先级
或环境变量）。因此报告里的 migration 计数**不代表每一次 migrate 调用**。

整份文件先全量校验再出报告：空、空白行、截断 JSON、重复键、布尔冒充数字、
NaN/Infinity、负时长、未知事件/相位、缺失必需相位、多余字段、无效 UTF-8 或
文件不存在都会非零退出，不打印部分报告、不回显原始输入。聚合统计（sum / median）
溢出为非有限值同样非法。

## 限制（报告里也会重复）

- v1：单个 schema fixture 内五个相位互不重叠，可相加；`fixture.migrate` 已包含
  migration 的 lock/apply，不能再把 migration 事件加回去（重复计数）。
- v2：模板 fixture 四个相位可相加，但 `fixture_total_ms` 已包含它们和相位间开销，
  不要把克隆相位再加到它上面。
- migration 事件可能独立出现；不要仅凭 PID 或 identity 把 fixture 行和 migration
  行强行 join。独立 migration 的 error 不等于失败用例。
- 任何跨调用、跨并发聚合的相位耗时之和都 **不等于** 墙钟加速比；两个对照用例的
  耗时也不预测整套测试的加速比。
- 报告里的 count 是“写出计时行的调用数”，不是测试总数。测试总数、失败数和墙钟
  时间看测试日志与 GitHub step 时长。

## 验收门槛

- STAGE 0/1：已满足（见阶段小节与结果页）。
- STAGE 2：已满足。CI run `34742275829` 中两个具名 repository 用例切到模板克隆并
  通过，其余用例保持旧 schema 路径；prepare/test/cleanup 全绿，JUnit 关联对比可用。
- Phase 3 第一批：**gate 已通过、已验证**。`1c83587`（run 34750664243）三个 job 全绿，
  两个 job 都 **1909/1909 passed、0 failed、0 skipped**、覆盖率 **81.76%**、prepare/
  cleanup 成功无残留。此前 `13be5e7` 的失败保留在结果页。实测诊断计数见结果页。
- Phase 3 第二批：**gate 已通过、已验证；planned scope 完成**。`0f3ad2a`（run
  34752963270）三个 job 全绿，两个 job 都 **1909/1909 passed、0 failed、0 skipped**、
  覆盖率 **81.75%**、prepare/cleanup 成功无残留；11 个 auth 候选在两个 job 都 PASS。
  实测计数 template 36 / schema 445 / migration 466 / prepare 1 / 记录 948。
- 阶段状态：stage 2 历史结论仍然有效且未被改写；第一批、第二批都已验证。**不再扩展
  范围**（不加 slot pool、不改并发），失败 run 只作为历史保留。
- 计划范围内共 **36 个 opt-in**（2 repo + 23 plans + 8 factors_repository + 3
  passkey_cas）；默认 schema 路径、危险的迁移/DDL/roles/source-URL 测试都未改动。

不要用两个用例或单次运行声称整套测试的收益或提速；`fixture_ms` 的 v1 估计与 v2 实际
口径不同，不能直接当同口径对比。缺配置仍硬失败。

**回滚要诚实分开两件事**：即使回退模板 DB 选择，也**应保留 Redis namespace 修复**——
全局共享 Redis 是独立的旧缺陷，与数据库选择无关，回退它会让退款队列再次跨测试串扰。

- 旧的默认 API 语义不变：`test_state`/`test_state_with_max_connections` 仍传
  `RedisKeyspace::default`（legacy），`db_isolation` 默认仍是 schema 路径，没有全局
  DB/Redis 模式开关。
- 若只回退模板 DB 选择，需为本批显式提供 schema + 独立 Redis 的夹具，再替换调用点
  和 import；该组合入口目前未提供。不能直接换回使用 legacy Redis 的 `test_state()`，
  否则会丢失隔离并触发新增断言。故障注入的 keyspace/时钟及健康 store 恢复逻辑应保留。
- 若只回退 Redis 修复：把非 legacy keyspace 换回 `RedisKeyspace::default`，并撤销新增
  的两个非 legacy 早期断言；这会让退款队列回到跨测试串扰的旧行为，只在明确接受该
  缺陷时使用。
