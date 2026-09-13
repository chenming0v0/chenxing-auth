# DB 计时基线与模板生命周期（issue #710）

目标：在把 schema 夹具切换成模板克隆时，先量出真实成本再逐步落地。这里记录
各阶段、当前配置、JSONL 契约和限制。

## 阶段

- **STAGE 0（schema 基线）**：测量 schema 夹具成本。CI run
  [34734563113](https://github.com/chenming0v0/chenxing-auth/actions/runs/34734563113)
  （SHA `ff63326`）全绿：1876 用例通过；JSONL 983 行（481 fixture + 502
  migration）；五个 fixture 相位里 `fixture.migrate` 占 87.56%。
- **STAGE 1（模板基础设施，已完成）**：模板生命周期 + JUnit 关联落地。CI run
  [34739022956](https://github.com/chenming0v0/chenxing-auth/actions/runs/34739022956)
  （SHA `8914118`）全绿：1907 用例通过、覆盖率 81.70%、两个 job 的
  prepare/cleanup 都成功；wrapper 层 `template_fixture=0`、
  `template_prepare_ms=1250.329`。该 run 也提供了下面两个候选用例的 schema 基线。
- **STAGE 2（试点切换，本阶段）**：只把两个具名 repository 用例切到模板克隆，
  **其余所有用例保持旧 schema 路径**。切换后的重复运行、执行顺序、缺配置降级等
  稳健性测试与 CI 对比仍在进行；在拿到稳定证据前，不宣称任何测得的加速。
- **扩大试点（未批准）**：只有在重复运行与 CI 对比稳定显示收益后，才评估扩大
  范围。第一批尚未 approved，issue 也尚未完成。

## 模板试点范围（stage 2）

`tests/storage/integration/repository.rs` 中只有这两个用例显式 opt-in 模板克隆：

- `integration::repository::postgres_repositories_round_trip_users_and_clients`
- `integration::repository::postgres_transaction_user_insert_and_missing_client_paths_work`

其余用例一律走旧 schema 路径。`--junit` 关联的就是这两个 identity，用于在切换
前后对比同一用例。

## 候选用例 schema 基线

来自 STAGE 1 run
[34739022956](https://github.com/chenming0v0/chenxing-auth/actions/runs/34739022956)
（切换前，旧 schema 路径）：

| identity | test_elapsed_ms | fixture_ms | body_residual_ms |
| --- | --- | --- | --- |
| `integration::repository::postgres_repositories_round_trip_users_and_clients` | 2490.000 | 1550.225 | 939.775 |
| `integration::repository::postgres_transaction_user_insert_and_missing_client_paths_work` | 1725.000 | 1692.841 | 32.159 |

`fixture_ms` 是 v1 五阶段之和的估计（缺相位间开销），`body_residual_ms` 含测试体、
运行时开销和诊断写入，不是纯 body。这两个数字是切换前的对照，**不代表任何已测得
的加速**；两张单用例的耗时也不预测整套测试的加速比。

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

测试进程通过 `CHENXING_TEST_DB_TIMING_FILE` 指定 JSONL 输出路径。**完整套件与
覆盖率验证由 CI 负责**，本地命令只是冒烟诊断，不替代 CI：

```bash
# 本地冒烟：只跑一个聚焦目标，唯一临时目录避免多次运行混行。
tmp="$(mktemp -d)"
CHENXING_TEST_DB_TIMING_FILE="$tmp/db-timing.jsonl" \
  ./test_sh/test.sh --test storage
python3 test_sh/db_timing_report.py "$tmp/db-timing.jsonl"

# 模板生命周期：显式给出变量后 prepare / cleanup。
export MIGRATION_DATABASE_URL=...   # owner 连接
export CHENXING_TEST_TEMPLATE_DATABASE=ctest_local_template
export CHENXING_TEST_DATABASE_PREFIX=ctest_local_
./test_sh/test_database.sh prepare
./test_sh/test_database.sh cleanup   # 失败也要跑
```

`--full`、`--gate`、`--coverage` 属编排者全量模式，默认只在 CI 失败需要本地
复现时才经授权运行，不作为本地默认示例。

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
（失败即让 job 失败），再跑报告（prepare 或 test 任一到达就执行，用 `--junit`
读 `target/nextest/default/junit.xml`），最后无条件上传
`db-timing-diagnostics`（报告文本 + 原始 JSONL + JUnit）。`coverage` job 同样
prepare/cleanup，但**不注入 timing 变量**、不产计时数据，覆盖率门槛
`--fail-under-lines 75` 与 `rust-coverage` 工件不变。

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

STAGE 0/1 门槛均已满足（见阶段小节）。STAGE 2 的门槛尚未满足：切到模板克隆后
还需要

- 重复运行确认模板克隆结果稳定（含执行顺序变化）；
- 缺配置（无 `CHENXING_TEST_*`）时旧 schema 路径可用；
- CI 对比切换前后同一对候选用例的 `test_elapsed_ms` / `fixture_ms`；
- 证据稳定后，才讨论扩大试点。

不要把 fixture 计数当成测试总数，也不要在拿到稳定对比前声称模板重构已有收益或
提速。第一批尚未 approved，issue 尚未完成。
