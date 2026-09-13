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

## Phase 3 第一批基线（23 个 plans 用例，schema/v1）

基线来自 STAGE 2 的同一 run [34742275829](https://github.com/chenming0v0/chenxing-auth/actions/runs/34742275829)
（`3ba5fba`，此时 23 个 `plans::` 用例仍是 schema 路径）。用原始 JSONL 与 JUnit 做
严格 join：每个 identity 恰好一行 fixture（`binary_name=plans`、`database_mode=schema`、
`outcome=ok`）且恰好一个 JUnit testcase（`classname=chenxing-auth::storage`、`name`
精确相等、无 failure/error/skipped/flaky/rerun）；缺失或重复都判失败，不做部分结果。
逐用例表与 JSON 见 `/tmp/opencode/issue710-stage3-plans-baseline/plans23_baseline.{md,json}`。

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

- `v1_phase_sum_ms` 是 schema 五阶段之和（估计，缺相位间开销）；将来的模板切换会发
  v2 `fixture_total_ms`（真实包裹计时），**口径不同**，不能直接当同口径对比。
- migration/lock（可辩护的 identity 映射：23 个 `plans::` migration 行与 23 个 fixture
  identity 集合完全一致、各 1 行、全 ok；不强行 join）：`migration_lock_wait_ms`
  n=23 / 累计 **9145.127 ms**，`migration_apply_ms` n=23 / 累计 **13638.559 ms**。
  这些是独立 migration 事件，模板模式下 prepare 的迁移会被 suppress，未来计数会减少。
- 单次运行采样合计，不是并行墙钟；未跑之前不做任何提速声明。

## Phase 3 第一批预期诊断计数（EXPECTED）

实现落地后的 CI（尚未运行）预期：`template_fixture` **25**（原 2 + 新增 23）、
`schema_fixture` **456**（479 − 23）、`schema_migration` **477**（500 − 23）、
测试总数 **1908**。以上是 **EXPECTED 预期值，不是实测**；实际以 CI 计数为准。

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
- **Phase 3 第一批（23 用例审计通过；实现进行中，CI 待跑）**：候选审计列出 7 个文件 /
  23 个 `plans::` 用例符合条件；实现正在进行，尚未有 CI 证据，不得宣称已完成或已绿。
  基线数字与预期计数见上一节。
- 回滚方式：stage 2 改回 `tests/storage/integration/repository.rs` 的两个调用点；
  phase 3 第一批删掉 23 处 `plans` helper 调用并恢复对应 import。默认 schema API 不变，
  模板始终是逐用例/逐文件 opt-in，根 `db_isolation` 默认不变。
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
