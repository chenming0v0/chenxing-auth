# DB 计时与模板重构结果（issue #710）

本页只放**可复现的 CI 证据与数字**。操作流程、命名空间规则、JSONL 契约和限制见
[`test_sh/db_timing.md`](./db_timing.md)；本页不复述流程。

所有数字来自对应 run 下载的 `db-timing-diagnostics`（原始 JSONL、报告文本、
JUnit）与 job 日志。相位之和、`fixture_total_ms`、候选对比都由
`test_sh/db_timing_report.py` 从原始 JSONL 重新导出。

## 基线标识修正

| 标签 | commit | run |
| --- | --- | --- |
| STAGE 0（schema 基线） | `ff63326` | [34734563113](https://github.com/chenming0v0/chenxing-auth/actions/runs/34734563113) |
| 插桩前对照（无逐相位数据） | `60ac1a4` | [34708714258](https://github.com/chenming0v0/chenxing-auth/actions/runs/34708714258) |
| STAGE 1（模板基础设施） | `8914118` | [34739022956](https://github.com/chenming0v0/chenxing-auth/actions/runs/34739022956) |
| STAGE 2 失败尝试 | `e4b7bc7` | [34741173462](https://github.com/chenming0v0/chenxing-auth/actions/runs/34741173462) |
| STAGE 2 成功（试点切换） | `3ba5fba` | [34742275829](https://github.com/chenming0v0/chenxing-auth/actions/runs/34742275829) |
| STAGE 3 第一批（23 个 plans；coverage 失败） | `13be5e7` | [34748274304](https://github.com/chenming0v0/chenxing-auth/actions/runs/34748274304) |

## 总览（全部单次 CI 运行）

| 指标 | STAGE 0 `ff63326` | STAGE 1 `8914118` | STAGE 2 失败 `e4b7bc7` | STAGE 2 `3ba5fba` |
| --- | --- | --- | --- | --- |
| 用例（通过/失败/跳过） | 1876 / 0 / 0 | 1907 / 0 / 0 | quality 未跑；coverage 1907 / 0 / 0 | 1908 / 0 / 0 |
| 覆盖率（行） | 81.72% | 81.70% | 81.72%（coverage job） | 81.73% |
| schema_fixture 行 | 481 | 481 | — | 479 |
| schema_migration 行 | 502 | 502 | — | 500 |
| template_fixture（v2）行 | 0 | 0 | 0 | 2（都 ok） |
| template_prepare 行 | 0 | 1 | 1（error） | 1（ok） |
| quality prepare | — | 29s | **37s 失败** | 29s |
| quality test STEP | 510s | 507s | 跳过 | 486s |
| quality cleanup | — | 2s | 0s | 2s |
| quality nextest（纯运行） | 453.990s | 475.769s | — | 453.629s |
| quality step 和（prep+test+clean） | 510s（无模板步骤） | 538s | — | 517s |
| coverage nextest（纯运行） | 609.261s | 643.625s | 633.135s | 648.474s |
| coverage prepare/cleanup | — | 54s / 49s | 59s / 44s | 59s / 47s |
| coverage step 和（prep+step+clean） | 693s（无模板步骤） | 819s | 806s | 830s |

口径：`nextest（纯运行）` 一律取 nextest 的 `Summary [...]` 行；`test STEP`、各
`prepare/cleanup` 与 `step 和` 取 GitHub step 时间戳，不是纯测试时间。例如 STAGE 2
失败 run 的 coverage nextest 是 **633.135s**，而它的 coverage 测试步骤（含编译）
是 703s，两者不能混用。所有墙钟都是**单次运行**，runner 会波动，不构成稳定性能序列。

## 两个试点用例（name-specific）

`fixture_ms` 在 STAGE 1 是 v1 五阶段之和（估计，缺相位间开销），在 STAGE 2 是
v2 `fixture_total_ms`（真实包裹计时）。两者**口径不同**，差值不是纯同口径对比。

| identity（省略公共前缀 `integration::repository::`） | stage1 elapsed | stage2 elapsed | Δelapsed | stage1 fixture（v1 估） | stage2 fixture（v2 实） | Δfixture |
| --- | --- | --- | --- | --- | --- | --- |
| `postgres_repositories_round_trip_users_and_clients` | 2490.000 | 796.000 | −1694 ms | 1550.225 | 174.073 | −1376.152 ms |
| `postgres_transaction_user_insert_and_missing_client_paths_work` | 1725.000 | 221.000 | −1504 ms | 1692.841 | 183.366 | −1509.475 ms |

- 两用例 elapsed 合计 4215 → 1017 ms（Δ −3198 ms）；fixture 合计 3243.066 → 357.439 ms
  （Δ −2885.627 ms）。
- `body_residual_ms` 两侧都保留：stage1（v1 估）A **939.775**、B **32.159**；stage2（v2 实）
  A **621.927**、B **37.634**。它含测试体、运行时开销和诊断写入，非纯 body。
- **完整成本（聚合样本，不是并行墙钟）**：stage2 = `template_prepare` 1037.540 +
  两用例 JUnit elapsed 1017 = **2054.540 ms**；stage1 同两用例 elapsed = **4215 ms**。
  克隆/`fixture_total` 已包含在 JUnit elapsed 内，**不再重复相加**；构建与 cleanup
  成本另计在各自 step 和里。这是把采样到的分段工作加总，不代表并行墙钟时间。
- 本地对照（非 CI）：8914118 三次 A elapsed ~1467–2631 / fixture 1165–2345，B ~1166–2244 /
  fixture 1141–2196；本地 pilot `fixture_total` 约 131–180 ms/用例，CI 为 174.073 / 183.366。
- **不据此声称整套测试提速**：只有两个用例、单次运行、墙钟噪声大，且 CI runner 与本地
  不同。

## 模板准备与克隆成本（STAGE 2 `3ba5fba`，来自原始 JSONL）

- `template_prepare`：1 行，`template_prepare_ms = 1037.540`（该相位已内含内部
  `db::migrate`；prepare 期间的嵌套 migration 诊断被 suppress）。
- 模板克隆 `template_fixture`（v2）：2 行，都 ok。
  - 四相位之和 **277.709 ms**：`bootstrap_connection` 77.829、`database_clone_ms` 103.414、
    `pool_connect` 92.404、`sequence_reset` 4.063。显示的三个小数是各自独立四舍五入，
    相加会得 277.710，与全精度和 277.709 差 0.001 ms；这是舍入，不是算术错误。
  - `fixture_total_ms`：2 行合计 357.439 ms，median 178.720 ms（含相位间开销，故大于
    四相位之和）。
- 克隆相位与 `fixture_total_ms` 不可相加（重复计数）。

## 其余 migration / lock 总量

| 指标 | STAGE 0 | STAGE 1 | STAGE 2 |
| --- | --- | --- | --- |
| schema_fixture 五相和 | 528769.140 ms | 591624.791 ms | 479813.116 ms |
| 其中 `migrate` 占比 | 87.56% | 88.99% | 86.40% |
| `migration_lock_wait_ms` 合计（n） | 179373.678（502） | 224557.558（502） | 154521.183（500） |
| `migration_apply_ms` 合计（n） | 257265.917（501） | 279857.886（501） | 240108.619（499） |

每个 run 都有 2 行 migration `error`（`storage-8fa6ec70a9b2a19d`）：这是错误路径插桩，
**不是失败用例**。STAGE 2 全部 500 行 migration 都是 `database_mode=schema`，模板模式下
没有 migration 事件，确认 prepare 内部迁移诊断被抑制。

## 清理结果（两个 job）

STAGE 2 `3ba5fba` 两个 job 的 cleanup 都成功：
`clones_dropped=2 templates_dropped=1 already_absent=0`（两个试点克隆 + 一个模板）。

## Phase 3 第一批（23 个 plans 用例）：基线 vs 本次实测

23 个用例的 identity 集合、逐文件计数（`authorization_quota`3、`default_plan`5、
`entitlements`3、`plan_admin`5、`plan_boundaries`2、`plan_quota`3、`qps_limit`2）在
两次 run 中一致。基线用 schema/v1，本次用 template/v2，**口径不同**，不能当同口径对比。

**基线（`3ba5fba` / run 34742275829，schema/v1，严格 JSONL×JUnit join）**：逐用例表与
JSON 见 `/tmp/opencode/issue710-stage3-plans-baseline/plans23_baseline.{md,json}`。

| module | cases | elapsed_ms | v1_phase_sum_ms | body_residual_ms |
| --- | ---: | ---: | ---: | ---: |
| authorization_quota | 3 | 21436.000 | 9456.666 | 11979.334 |
| default_plan | 5 | 22442.000 | 4042.863 | 18399.137 |
| entitlements | 3 | 15352.000 | 4694.137 | 10657.863 |
| plan_admin | 5 | 16644.000 | 3645.006 | 12998.994 |
| plan_boundaries | 2 | 5593.000 | 1568.853 | 4024.147 |
| plan_quota | 3 | 15772.000 | 2061.812 | 13710.188 |
| qps_limit | 2 | 12091.000 | 1651.858 | 10439.142 |
| **合计** | **23** | **109330.000** | **27121.193** | **82208.807** |

基线 migration/lock（可辩护的 identity 映射：23 个 `plans::` migration 行与 23 个
fixture identity 集合完全一致、各 1 行、全 ok，不强行 join）：`migration_lock_wait_ms`
n=23 / 累计 **9145.127 ms**，`migration_apply_ms` n=23 / 累计 **13638.559 ms**。

**本次（`13be5e7` / run 34748274304，template/v2）**：

| 指标 | 基线（v1） | 本次（v2） | 备注 |
| --- | ---: | ---: | --- |
| 23 用例 elapsed 合计 | 109330.000 ms | **135146.000 ms** | +25816 ms（+23.6%） |
| 23 用例 fixture 指标 | v1 phase-sum 27121.193 | v2 `fixture_total` 7563.464 | 口径不同 |
| `fixture_total` median | — | 306.736 ms | 单次 run |
| 四相位之和 | — | 5685.507 ms | `bootstrap`1804.817 / `clone`1714.272 / `pool`2091.182 / `seq`75.237 |
| `elapsed − fixture_total` | 82208.807 | **127582.536 ms** | 非纯 body |

- 口径差异：v1 的每个用例相位含 `migrate`（整个 per-test 迁移）；v2 把它换成
  `database_clone_ms`，迁移只在模板构建时跑一次并单独记为 `template_prepare`。所以
  v1 phase-sum 与 v2 四相位之和不可比，v2 `fixture_total_ms` 才是旧 setup 区间最接近
  的对应量。
- **DB 初始化样本下降，但采样到的总 elapsed 上升 25816 ms**：这是单次 run 的采样合计，
  不是并行墙钟；不能据此声称整套测试或净收益改善。
- 质量墙钟（nextest 纯运行）453.629s → 588.631s，同样是单次噪声，无收益声明。

## 本次 run 实测：quality 通过 / coverage 失败

**实测诊断计数（quality job 工件，非预期值）**：总记录 **959**；
`template_fixture` v2 **25**（`integration_storage` 2 + `plans` 23，都 ok）、
`schema_fixture` v1 **456**、`schema_migration` v1 **477**、`template_prepare` **1**
（ok，`template_prepare_ms=532.625`）。报告重跑与工件逐字节一致，sha256
`0c1b14d1…`。

| job | 结论 | 用例 | 墙钟 |
| --- | --- | --- | --- |
| quality | **success** | **1908 / 1908 passed, 0 failed, 0 skipped** | nextest 588.631s；test STEP 628s；prepare 33s + test 628s + cleanup 1s = 662s |
| coverage | **failure** | 1820/1908 run：1819 passed、**1 failed**、0 skipped；88 not run | nextest 481.550s（中止）；prepare 43s + test 534s + cleanup 37s = 614s（中止，非完整可比） |

- cleanup 都成功：quality `clones_dropped=25 templates_dropped=1`；coverage
  `clones_dropped=6 templates_dropped=1`。coverage 克隆数少是失败中止的结果，不是泄漏。
- 覆盖率 **未产出**：失败中止在 `--fail-under-lines` 评估之前，没有 lcov/报告行，
  因此本 run **没有**覆盖率百分比。
- 失败的覆盖率用例：`plans::authorization_quota::assigned_plan_daily_and_monthly_limits_reject_authorizations`，
  coverage job 在 `tests/storage/plans/authorization_quota.rs:51:5` panic
  `assertion failed: matches!(result, AuthorizationCodeIssue::QuotaExceeded)`；
  **同一个用例在同一次 run 的 quality job 通过**（5.943s）。原因未查清——不称其为既有
  flake，也不归因于插桩。4 个 lifecycle 用例在两个 job 都通过，两个 job 的 prepare 都
  成功且日志里 `sessions remained` 计数为 0。
- **oracle 结论（确定的测试隔离缺陷）**：refund worker 会扫描 keyspace 级的退款队列，
  可能退还**其它测试**的 reservation，即使各测试的 Client ID 唯一；退款测试传
  `clock.now()+360` 给共用队列的 worker，这种测试安排会污染其它用例。
- **边界（不要越界推断）**：`13be5e7` 那次 CI 的具体交织**没有 reservation trace**，
  其因果关系仍属推断；这是**测试隔离**缺陷，不能据此声称生产 quota bug，也不能断言
  它就是历史失败的确切根因。

## Phase 3 第一批修复（本地聚焦运行时已通过，全量 CI 待跑）

- `tests/support/plans.rs`：`test_state_from_template` 为本测试签发新的
  `plans-<uuid>` `RedisKeyspace`，`finish_plan_env` 在 `AppState` 之前写入
  `config.redis_keyspace`；`test_state`/`test_state_with_max_connections` 仍传
  `RedisKeyspace::default`（legacy），`wallet` 15 个 fixture 不动。
- `authorization_quota.rs`：故障注入改用与 fixture 相同的 keyspace 与时钟，并保存、
  恢复健康的 `AuthorizationCodeStore`；**保留全部既有 quota 断言与 limit**，另加两个
  早期断言要求模板 fixture 配置为非 legacy。
- 新增确定性 Redis-only 回归
  `tests/storage/redis/refund_namespace.rs::refund_queue_is_shared_across_client_ids_within_a_keyspace`：
  共享私有命名空间下 B 的 worker drain A+B 共 3 条、A 之后可再消费；隔离命名空间下
  B 只 drain 1 条、A 保持 2/2 且第三次 `DailyExceeded`、随后 A 自己退回 2 条。不触碰
  真实 legacy 队列，无 sleep、无并发。
- 本地聚焦运行时已通过（见下），但新全量 CI 尚未跑；预期新增后测试总数 **1909**，
  DB 计时 fixture 计数预计不变（template 25、schema 456、migration 477）——**预期，
  非观测**。

### 本地运行时证明（parent，已通过）

- `cargo check --all-targets --all-features` + clippy 通过。
- 临时 PG16/Redis 上，聚焦过滤
  `binary(storage)&(test(/^plans::/)|test(/^redis::refund_namespace::/))`：**24/24 passed**，
  nextest **4.092s**，155 skipped（日志 `target/test-logs/20260913-174659`）。回归的
  control 与 isolation 断言都实际执行。
- 清理：23 clones + 1 template；残留 namespace DB 0、source public tables 0。
- 这是**本地聚焦**证据：**新全量 CI 仍未跑**，也没有历史交织的证明；不因此宣称 batch
  完成或 gate 通过。

## Phase 3 第一批回滚

回滚要诚实分开两件事：**即使回退模板 DB 选择，也应保留 Redis namespace 修复**，
因为全局共享 Redis 是独立的旧缺陷，与数据库选择无关。

- 旧的默认 API 语义不变：`test_state`/`test_state_with_max_connections` 仍传
  `RedisKeyspace::default`（legacy），`db_isolation` 默认仍是 schema 路径，没有全局
  DB/Redis 模式开关。
- 若只回退模板 DB 选择，需为本批显式提供 schema + 独立 Redis 的夹具，再替换调用点
  和 import；该组合入口目前未提供。直接换回 `test_state()` 会重新使用 legacy Redis，
  丢失隔离并触发新增断言。故障注入的 keyspace/时钟及健康 store 恢复逻辑应保留。
- 若只回退 Redis 修复：把非 legacy keyspace 换回 `RedisKeyspace::default` 并撤销两个
  非 legacy 早期断言；这会让退款队列回到跨测试串扰的旧行为，只在明确接受该缺陷时使用。
- `13be5e7` 初始切换的“只换 fixture 获取方式、断言体不变”描述仅指**初始**那一步；
  本次后续修复有意改动测试注入 wiring 并新增 guard/回归，但未削弱任何 quota 断言。

## STAGE 2 失败尝试与修正

- `e4b7bc7`（run 34741173462）quality：`Prepare template database` 以观测到的
  `sessions remained on template` 失败。原实现只检查一次模板的服务端后端连接数；日志
  没有记录残留后端的身份及时序，因此不能据此断言具体竞态。失败导致
  `Run Rust tests in parallel` 被跳过，随后 report
  步骤因强制 `--junit` 而级联失败并写入空 summary。coverage job 同 commit 成功
  （1907 通过、81.72%、两个克隆清理）。
- 修正：prepare 增加有界宽限轮询 → 按 datname 绑定 terminate → 再轮询，以收敛
  “疑似仍有后端连接”的场景；report 步骤在 tests 被跳过时省略 `--junit`，为非空才写
  summary。
- `3ba5fba`（run 34742275829）验证：quality prepare 成功、tests 实际运行、report 带
  `--junit` 成功；重跑报告与工件报告逐字节一致
  （sha256 `cd225e25…`）。4 个生命周期用例在 quality 与 coverage 均通过。

**局限**：CI 成功只验证了这一次观测到的运行，不能证明所有瞬时场景（如关闭竞态的其他
时序）都不可能复现。

## 阶段状态

- **Phase 2 门槛已通过**：两个具名 repository 用例在 CI 中切到模板克隆并稳定通过，其余
  用例仍走 schema 路径。
- **Phase 3 第一批（已实现；gate 未通过；扩大暂停）**：23 用例审计通过，初始实现见
  `13be5e7`，run 34748274304。quality job 全绿（1908 通过、计数达预期），但 coverage
  job 有 1 个用例失败并中止，阶段 gate **未通过**；oracle 定位到确定的共享 Redis 退款
  队列测试隔离缺陷，修复的本地聚焦运行时已通过（24/24）、新全量 CI 尚未跑，
  因此**暂停**进一步扩大，本批不得宣称完成。实测数字见上一节。
- 阶段历史保持：stage 2 的两个 repository 用例结论仍然有效且未被改写；phase 3 第一批
  是在其之上新增的 23 个 `plans::` 用例。
- 回滚方式见上一节：stage 2 改回 `tests/storage/integration/repository.rs` 的两个
  schema 调用点；phase 3 第一批需要显式的 schema + 独立 Redis 夹具，不能仅改回
  legacy `test_state()`；**保留 Redis namespace 修复**。
  默认 schema API 不变，模板始终是逐用例/逐文件 opt-in，根 `db_isolation` 默认不变，
  没有全局 DB/Redis 模式开关，也没有自动回退。
- 缺变量仍是硬失败：`test_database.sh` 在编译前对缺失（含显式空串）的必需变量报错，
  `MIGRATION_DATABASE_URL` 不回退到 `DATABASE_URL`。

## 源文件行数检查（#710 变更）

按整个变更集核对，而不是默认的“仅未提交改动”检查：

```
python3 .codex/skills/src-line-limit/scripts/check_src_lines.py --base 60ac1a4
```

- 检查 8 个变更的 `src` 文件，**3 个弱警告、0 个错误**：
  - `src/db/migration_compat.rs` 447 行
  - `src/db/mod.rs` 445 行
  - `src/db/test_timing/tests.rs` 329 行
- 三个都低于 500 硬上限，仅触发 >300 的弱警告；本阶段不要求重构 `src`。
- 说明：默认的按“未提交改动”检查当时没有匹配到文件，返回的是“无匹配文件”，**不等于**
  整个变更集零警告。这里记录的是 `--base 60ac1a4` 的完整结果。
