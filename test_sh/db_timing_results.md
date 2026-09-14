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
| STAGE 3 第一批修复后（全绿，已验证） | `1c83587` | [34750664243](https://github.com/chenming0v0/chenxing-auth/actions/runs/34750664243) |
| STAGE 3 第二批（11 个 auth；全绿，已验证） | `0f3ad2a` | [34752963270](https://github.com/chenming0v0/chenxing-auth/actions/runs/34752963270) |

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

## Phase 3 第一批（23 个 plans 用例）：基线 vs v2 实测

23 个用例的 identity 集合、逐文件计数（`authorization_quota`3、`default_plan`5、
`entitlements`3、`plan_admin`5、`plan_boundaries`2、`plan_quota`3、`qps_limit`2）在
各 run 中一致。基线用 schema/v1，v2 用 template/v2，**口径不同**，不能当同口径对比。

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

**先前失败 run（`13be5e7` / run 34748274304，template/v2）**：

| 指标 | 基线（v1） | `13be5e7`（v2） | 备注 |
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

**修复后 green（`1c83587` / run 34750664243，template/v2；23 用例原始数据
`plans23_1c83587.json`）**：elapsed 合计 **79253.000 ms**（median 3677）、
`fixture_total` **4483.971**（median 189.326）、`elapsed − fixture_total`
**74769.029 ms**；四相位 `bootstrap` 1046.349 / `clone` 1068.189 / `pool` 1262.120 /
`seq` 45.792，raw 合计 **3422.449**（各相位显示值独立四舍五入后相加会得 3422.450，
差 0.001 ms 是舍入）；`template_prepare_ms` 409.737。相对 `13be5e7` 明显更低，
但仍是**单次 run 采样**，受 live-backend/调度波动影响，不能声称因果性或稳定的整套
加速。

- **完整成本（采样，非并行墙钟）**：`template_prepare`(409.737) + 23 用例
  elapsed(79253.000) = **79662.737 ms**；克隆已含在 elapsed 内，**不重复相加**。
- 基线 `3ba5fba` 的 v1 elapsed 为 109330.000 ms（口径不同），仅作对照。

## 先前失败 run（`13be5e7`）：quality 通过 / coverage 失败

保留此失败记录与口径区分。**实测诊断计数**（quality job 工件）：总记录 **959**；
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
- **根因定位结论（确定的测试隔离缺陷）**：refund worker 会扫描 keyspace 级的退款队列，
  可能退还**其它测试**的 reservation，即使各测试的 Client ID 唯一；退款测试传
  `clock.now()+360` 给共用队列的 worker，这种测试安排会污染其它用例。
- **边界（不要越界推断）**：`13be5e7` 那次 CI 的具体交织**没有 reservation trace**，
  其因果关系仍属推断；这是**测试隔离**缺陷，不能据此声称生产 quota bug，也不能断言
  它就是历史失败的确切根因。

## 修复后 green run（`1c83587` / run 34750664243，三个 job 全绿）

**实测诊断计数**：959 记录= `template_fixture` 25（`integration_storage` 2 + `plans` 23，
都 ok）、`schema_fixture` 456（含 `wallet` 15 仍在 schema）、`schema_migration` 477、
`template_prepare` 1 ok（`template_prepare_ms=409.737`）；**v2 migration 事件 = 0**
（模板内迁移被 suppress）。报告带 `--junit` 重跑与工件逐字节一致，sha256
`f6365062…`。

| job | 结论 | 用例 | 墙钟 |
| --- | --- | --- | --- |
| quality | **success** | **1909 / 1909 passed, 0 failed, 0 skipped** | nextest 396.906s；test STEP 430s；31 + 430 + 3 = 464s |
| coverage | **success** | **1909 / 1909 passed, 0 failed, 0 skipped** | nextest 637.499s；test STEP 714s；56 + 714 + 46 = 816s |

- 覆盖率 **81.76% ≥ 75%**（LF 47191、LH 38585；此前 81.73%）。
- 两个 job 都 `clones_dropped=25 templates_dropped=1 already_absent=0`；无 `sessions
  remained`。
- 两个受影响 quota 用例、新 `refund_namespace` 回归、lifecycle 4 个在两个 job 都 PASS。
- 测试证明的是命名空间边界这一机制，**不是**历史的精确交织；也不声称生产 quota bug。

## STAGE 3 第二批 green run（`0f3ad2a` / run 34752963270，三个 job 全绿）

**实测诊断计数**：948 记录 = `template_fixture` **36**（`integration_storage` 2 +
`plans` 23 + `auth_factors_repository` 8 + `passkey_cas` 3，都 ok）、`schema_fixture`
**445**（含 `wallet` 15 仍在 schema）、`schema_migration` **466**、`template_prepare`
**1** ok（`template_prepare_ms=1304.985`）；**v2 migration 事件 = 0**。报告带 `--junit`
重跑与工件逐字节一致，sha256 `32570195…`。

| job | 结论 | 用例 | 墙钟 |
| --- | --- | --- | --- |
| quality | **success** | **1909 / 1909 passed, 0 failed, 0 skipped** | nextest 544.034s；test STEP 575s；step sum 614s |
| coverage | **success** | **1909 / 1909 passed, 0 failed, 0 skipped** | nextest 641.638s；step sum 823s |

- 覆盖率 **81.75% ≥ 75%**（LF 47191、LH 38577）。
- 两个 job 都 `clones_dropped=36 templates_dropped=1 already_absent=0`；无
  `sessions remained`。
- 11 个 auth 候选、两个 plans quota 用例、`refund_namespace` 回归、lifecycle 4 个在两个
  job 都 PASS。

### 11 个 auth 候选（`factors_repository`8 + `passkey_cas`3）

- 基线 `1c83587`（schema/v1，从该 run 工件核实）elapsed **10327 ms**、v1 phase sum
  **9349.585 ms**。
- 本次 `0f3ad2a`（template/v2）elapsed **5666 ms**、`fixture_total` **4358.251 ms**
  （median 366.832）；clone 相位 bootstrap 379.992 / `database_clone` 2540.287 /
  pool_connect 779.198 / sequence_reset 289.223。
- **口径不同**：v1 phase sum 含 per-test `migrate`+`drop_create_schema`，v2 换成
  `database_clone_ms` 并把迁移并到 `template_prepare` 跑一次；`fixture_total` 才是旧
  setup 区间最接近的对应量。

### 当前 36 个 opt-in 的 cohort（单次 run，v2）

| cohort | count | elapsed total ms | fixture_total total ms |
| --- | ---: | ---: | ---: |
| plans23 | 23 | 77047 | 11212.050 |
| repo2（integration_storage） | 2 | 834 | 364.237 |
| auth11 | 11 | 5666 | 4358.251 |
| **all36** | **36** | **83547** | **15934.538** |

- **完整当前成本（采样，非并行墙钟）**：`template_prepare`(1304.985) + all36
  elapsed(83547) = **84851.985 ms**；克隆已含在 elapsed 内，**不重复相加**。
- `elapsed − fixture_total` = 67612.462 ms，含 clone-less body + 调度等开销，非纯 body。
- **不要**把某些聚合当成 `1c83587` 基线：`1c83587` 的实际 template25（2 repo + 23
  plans，从该 run 工件核实）是 elapsed **80141 ms** / fixture_total **4769.410 ms** /
  prepare 409.737，与本次 23+2 的 77881 / 11576.286 是不同 run、不能混标。本次 23 个
  plans 的 `database_clone` 合计（6526 ms）明显高于 `1c83587`（1068 ms）而 elapsed 相近
  （77047 vs 79253）。这里只记录观测差异，其原因未单独验证，不作因果推断。

## Phase 3 第一批修复（已由 `1c83587` 全量 CI 验证）

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
- 现已由 `1c83587` 全量 CI 验证（1909/1909、81.76%、cleanup 无残留）。本地聚焦运行时
  （`24/24 passed`，日志 `target/test-logs/20260913-174659`）作为补充保留。

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
- **Phase 3 第一批（gate 已通过、已验证）**：23 用例审计通过，初始实现 `13be5e7`
  当期 coverage 失败（见“先前失败 run”）。Redis 隔离修复后 `1c83587` 三个 job 全绿，
  两个 job 都 1909/1909、覆盖率 81.76%、cleanup 无残留；实测数字见对应小节。
- **Phase 3 第二批（gate 已通过、已验证；planned scope 完成）**：11 个 auth 用例
  （`factors_repository`8 + `passkey_cas`3）通过 `0f3ad2a`（run 34752963270）三个 job
  全绿，1909/1909、覆盖率 81.75%、cleanup 36+1 无残留；实测计数 template 36 /
  schema 445 / migration 466 / prepare 1 / 记录 948。实测数字见对应小节。
- **范围验收**：计划内共 **36 个 opt-in**；默认 schema API 与路径保留；迁移/DDL/
  roles/source-URL 类用例未改；phase 3 生产逻辑未动；actor pool 共享与 max8 保留；
  plans 私有 Redis namespace 与 wallet legacy 不变；无 flush/truncate/并发改动。
- 阶段历史保持：stage 2 的两个 repository 用例结论仍然有效且未被改写；phase 3 第一、
  二批是在其之上新增的 23 + 11 个用例。失败 run（`e4b7bc7`、`13be5e7`）仅作历史保留。
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

## 方向修正后的首次全绿（分片架构，`8f7c27f` / run 34845247253）

旧方向（STAGE 0–3 逐批 template 化）没有让 CI 变快，原因与完整分析见
[`test_sh/db_timing.md`](./db_timing.md) 的「方向修正」一节。本节记录转向后
**第一次全绿的实测**，只报 job/step 墙钟，不报聚合相位和。

| 指标 | 旧架构基线 `f644df5` | 旧架构最后三次 | 新架构 `8f7c27f` |
| --- | ---: | ---: | ---: |
| 工作流总时长 | **14m37s** | 14m42s / 14m57s / 14m37s | **7m11s** |
| quality / 静态 job | 12m54s（含整套 nextest） | 12m36–13m45s | **2m13s**（不再跑集成测试） |
| coverage 关键路径 job | 14m11s | 14m30s / 14m35s | **0m12s**（只合并，不再重跑测试） |
| 最慢测试 job | — | — | 6m29s（shard 3，4 个分片并行） |
| 用例 | 1909 | 1909 | **1909/1909**（477+477+477+478，0 failed） |
| 行覆盖率 | 81.75%（原生 LF/LH） | 81.75%–81.76% | **81.88%**（合并阈值，门槛 75%） |

分片 job 的 step 墙钟（run 34845247253）：

| shard | Prepare template | Run tests | Cleanup template | job 合计 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 37s | 173s | 31s | 5m01s |
| 2 | 49s | 257s | 44s | 6m29s |
| 3 | 52s | 251s | 47s | 6m29s |
| 4 | 47s | 247s | 43s | 6m16s |

- 每个分片只跑 `slice:m/4` 的约 477 个用例，nextest 报
  `Starting 477 tests across 8 binaries (1432 tests skipped)`，分片切分生效。
- **锁竞争已被摊薄**：旧结构里 445+ 个 schema 路径测试排同一把 session 级
  `pg_advisory_lock`（锁 ID 只由 `current_database()` 生成，见
  `src/db/migration_compat.rs:38-47`）；现在四个分片各自连独立 PostgreSQL 实例，
  锁不再跨分片共享。这正是总时长从 14m37s 降到 7m11s 的主因。

### 四分片阶段观察到的剩余成本

- **`Cleanup template database` 每个分片仍编译 38–51s**：日志显示它在重新编译
  ring/rustls/sqlx/reqwest/lettre/`chenxing-auth`。这是四个分片各付一次的浪费，
  但**根因尚未定位**。
- `Prepare template database` 每个分片 37–53s，其中大部分同样是编译
  `test_database` 示例与依赖，而非建库本身（建库只需 `template_prepare_ms`
  约 1s 量级）。
- 该阶段分片数为 4；加到 8 的收益需要新的实测，不能靠推算。

#### 两次「省掉 cleanup 重编」的尝试都失败（已回退，不要重复）

两次都基于**未经验证的假设**就改了 CI，结果一次是净回归、一次完全无效。记录在此
避免重复同样的错误：

1. **独立 `CARGO_TARGET_DIR=target/test-db-tool`**（`22c65f3`）：假设是
   `cargo-llvm-cov` 的默认 `cargo clean` 清掉了普通 dev 产物。实测**净回归**——
   该目录不在 rust-cache 覆盖范围内，`prepare` 从 48s 涨到 **111–141s**，而
   `cleanup` 只省下约 45s，工作流从 7m20s **恶化到 8m17s**。热缓存重跑仍是
   111–139s，确认不是冷缓存的一次性成本。
2. **`cargo llvm-cov nextest --no-clean`**（`53536d5`）：假设同上，只是换个开关。
   实测**完全无效**，cleanup 仍重编 **38–51s**（`--no-clean` 只影响
   `cargo clean`，不改变 llvm-cov 让普通 target 失效的行为）。

两处改动都已回退。负面结论已写进
`test_sh/test_db_timing_ci_contract.py` 的契约测试，防止再次引入。

顺带确认的一件事实：`cargo clean -p chenxing-auth` 在本地会删除
**10281 个文件 / 22.2 GiB**（`cargo clean --dry-run` 实测），所以「谁在动
`target/`」这件事值得继续查，但上面的两种猜测都不是答案。

### 口径边界

- 三次连续全绿的工作流总时长：`8f7c27f` **7m11s**、`5f3875f` **7m20s**、
  `22c65f3` 8m17s（含上面第 1 项的错误改动）。前两次是未叠加失败改动的架构，
  中位数 **7m15.5s**，低于 8 分钟目标。`22c65f3` 因为带错误改动而偏慢，不作为
  目标架构样本。回退后的 run 会补第三个干净样本。
- 覆盖率用 `test_sh/merge_lcov.py` 合并各分片 lcov（同一行取最大值），与原生
  LF/LH 口径接近但不等价：它只累计有 `DA` 记录的行，因此数值可能略高于或低于
  原生值。真实工件上的对照为合并 81.88% 对原生 81.75%，两者都远高于 75% 门槛。
- 失败上报的两条链路已修：首次 run（`4f9b375`）暴露了合并步骤对 artifact 嵌套
  路径的错误假设（`download-artifact` 会按 artifact 名建一层子目录），已改为按
  文件名递归查找并补回归测试（`8f7c27f`）。

## 八分片与容器回收（实现完成，性能待 CI 验证）

本轮把 matrix 和 `SHARDS` 同步改为 8，仍由同一个分母控制 nextest 的 slice 划分
和 lcov 合并的完整性检查。契约测试比较配置值与完整的 `1..N` 分片 ID，防止只改
分母、漏分片或重复分片。行覆盖率门槛仍为 75%，测试集合和 Rust 配置不变。

移除测试 job 末尾的 `Cleanup template database`：这些 PostgreSQL / Redis 是 job
专属 service container，GitHub 在 job 完成时销毁它们，数据库无需再单独清理。
依据：[GitHub service container 生命周期](https://docs.github.com/en/actions/concepts/use-cases/about-service-containers)。
本地 cleanup wrapper 与 platform 生命周期回归仍保留；这是省掉一次冗余调用，
**不代表已定位或修复重新编译的根因**。

### 回退后四分片基准（`54d36f7` / run 34851342516）

以下时间来自 [GitHub run](https://github.com/chenming0v0/chenxing-auth/actions/runs/34851342516)
及 jobs API 的 `started_at` / `completed_at`，是墙钟而非编译日志内的分项估算：

| shard | Prepare template | Run tests（含编译） | Cleanup template | job 合计 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 53s | 249s | 49s | 6m38s |
| 2 | 48s | 217s | 43s | 6m13s |
| 3 | 50s | 259s | 45s | 6m35s |
| 4 | 54s | 261s | 53s | 6m48s |

- run 创建于 13:46:34 UTC；quality 于 13:49:22 完成，coverage 于 13:53:40 完成，
  **质量检查完成耗时 7m06s**。
- Apifox 从 13:53:42 跑到 14:00:58，耗时 **7m16s**；run 于 14:00:59 更新为成功，
  **工作流总时长 14m25s**，不能称为「工作流约 7 分钟」。
- 上文的两个干净历史样本及其 7m15.5s 中位数不足以证明三次验收；这次回退后的
  干净样本又暴露了 Apifox 对总时长的影响。不能据此宣称连续三次 ≤ 8 分钟已达成。

本轮预期减少 cleanup 的 43–53s，并通过更多独立实例缩短测试执行，但编译、缓存、
runner 排队、用例分布及外部同步仍会影响墙钟。必须用同一配置的三次成功 run，分别
记录全部测试通过情况、合并覆盖率、最慢分片、质量检查完成耗时、Apifox 和工作流
总时长，再报告收益；目前没有八分片运行结果。

本地轻量验证：135 项 DB timing / CI / 合并契约测试、模板 wrapper、部署契约
（含部署 Compose 解析）、运行器契约、生产 Compose 解析、Action 固定引用及两个
workflow 的 YAML 基础结构检查通过。CI 内嵌 shell 与安装脚本语法、发布产物和
SHA256SUMS 声明检查通过；四种内存内错误配置（分母错误、缺片、重复、越界）都被
分片契约拒绝。`src-line-limit` 默认增量检查没有匹配文件，因为本轮未修改 `src`；
这不是全仓零警告结论。本地没有运行 Rust 全量测试，也没有测出新的覆盖率数字。
