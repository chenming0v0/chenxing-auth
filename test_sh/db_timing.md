# DB 计时基线（issue #710 STAGE 0）

STAGE 0 只做一件事：在动模板重构之前，先把数据库夹具和迁移的真实成本量出来。
这里没有模板、没有 schema 复用，只有「计时 → JSONL → 报告」这条链。基线必须
先证明迁移（migration）和迁移锁等待（lock wait）是主要成本，否则后面的模板
重构就是拍脑袋。

## 用法

测试进程通过环境变量 `CHENXING_TEST_DB_TIMING_FILE` 指定 JSONL 输出路径。
**完整套件与覆盖率验证由 CI 负责**（CI 的 `quality` job 跑全量并产出基线），
本地命令只是冒烟诊断，不替代 CI。本地自测只跑一个聚焦目标，并用唯一临时目录
输出，避免多次运行的行混进同一文件：

```bash
# 本地冒烟：单个聚焦目标即可验证计时链是否打通。
tmp="$(mktemp -d)"
CHENXING_TEST_DB_TIMING_FILE="$tmp/db-timing.jsonl" \
  ./test_sh/test.sh --test storage
python3 test_sh/db_timing_report.py "$tmp/db-timing.jsonl"
```

`--full`、`--gate`、`--coverage` 属编排者全量模式，默认只在 CI 失败需要本地
复现时才经授权运行，不作为本地默认示例。

报告器只读文件、不连数据库、不编译任何东西：

```
python3 test_sh/db_timing_report.py PATH
```

CI 的 `quality` job 在 `Run Rust tests in parallel` 步骤设置该变量（仅此一处，
步骤级作用域），测试结束后立即用同一个报告器出报告，写入 step summary，并把
报告文本和原始 JSONL 作为 `db-timing-diagnostics` 工件上传。上传步骤无条件执行
（`if: always()`）：测试失败、甚至测试步骤被跳过时都会尝试上传已存在的文件
（文件不存在只警告，不失败）。报告步骤则在测试步骤未被跳过时执行；报告数据非法
或缺失时报告步骤失败。`coverage` job 不注入该变量、不产出计时数据。

## JSONL 契约

每一行一个 JSON 对象，只有两种事件，元数据键完全一致：

`version, event, binary_name, test_identity, pid, database_mode, outcome, phases_ms`

- `fixture`：成功时 `phases_ms` 恰好有 `bootstrap_connection`、`drop_create_schema`、
  `pool_connect`、`migrate`、`sequence_reset`；失败时允许只包含已到达的相位。
  固定 ID 用例跳过 `sequence_reset` 记 0。重复调用不去重。
- `migration`：成功时恰好有 `migration_lock_wait_ms` 和 `migration_apply_ms`；
  连接获取失败可缺 lock，未执行到 apply 可缺 apply（apply 存在则 lock 必存在）。

整份文件先全量校验再出报告：空文件、空白行、截断 JSON、重复键、布尔冒充数字、
NaN/Infinity、负时长、未知事件/相位、缺失必需相位、多余字段、无效 UTF-8 或
文件不存在都会非零退出，且不打印部分报告、不回显原始输入。聚合统计（sum /
median）一旦溢出为非有限值也按非法处理，不会打印半截报告。

## 限制（报告里也会重复）

- 同一个 fixture 内的五个相位互不重叠，可以在单次 fixture 内相加。不能相加的是
  `fixture.migrate` 与 migration 事件的 lock/apply：`migrate` 是包含后者的嵌套
  区间，相加会重复计数。migration 事件也可能独立出现，不要仅凭 PID 或 identity
  把 fixture 行和 migration 行强行 join。
- 任何跨调用、跨并发聚合的相位耗时之和都 **不等于** 墙钟加速比。
- 报告里的 count 是「写出计时行的 fixture/migration 调用数」，不是测试总数。
  测试总数、失败数和墙钟时间看测试日志与 GitHub step 时长，二者分开记录。

## 验收门槛

STAGE 0 的验收是证据性的：CI 基线必须显示 migration / migration lock wait 是
夹具成本的主要来源，然后才进入模板重构（STAGE 1）。不要把 fixture 计数当成
测试总数，也不要在没有基线数据时声称模板重构有收益。
