#!/usr/bin/env python3
"""辰星认证中枢 - 数据库计时 JSONL 报告器（issue #710 STAGE 0）。

用法：

    python3 test_sh/db_timing_report.py PATH

`PATH` 是测试进程写出的 JSONL 文件。文件里每一行是一个 JSON 对象，事件类型
只有两种：`fixture`（测试夹具）和 `migration`（迁移执行）。两种事件共享同一组
元数据键（version/event/binary_name/test_identity/pid/database_mode/outcome/
phases_ms），只有 `phases_ms` 的相位名不同。

本脚本先校验**整个**文件，全部合法才打印报告；任何一行不合法都会以非零退出，
并且不打印部分报告、不回显原始输入或其中的敏感字段/错误文本。

契约要点（与 Rust 侧写入方共享，修改前先改契约）：

- `fixture` 成功时 `phases_ms` 恰好包含 bootstrap_connection、drop_create_schema、
  pool_connect、migrate、sequence_reset 五个相位。固定 ID 用例跳过 sequence_reset
  时该值为 0（仍然存在）。
- `fixture` 失败时允许只包含已到达的相位（含失败相位），键集合是五个相位的子集。
- `migration` 成功时 `phases_ms` 恰好包含 migration_lock_wait_ms 和
  migration_apply_ms。失败时允许缺失：连接获取失败可缺 lock，未执行到 apply 可缺
  apply；反过来 apply 存在则 lock 必须存在。
- 重复的 fixture 调用**不去重**，一次调用就是一行。
- 为空、含空白行、JSON 截断、重复键、布尔冒充数字、NaN/Infinity、负时长、未知
  事件或未知相位、缺失必需相位、多余字段，全部判为非法。聚合统计溢出为非有限
  值同样判为非法，且不打印半截报告。

报告只汇总已经到达的相位的 count/sum/median/p95/max（毫秒，最近秩 p95）。
同一个 fixture 内的五个相位互不重叠，可以在单次 fixture 内相加；不能相加的是
`fixture.migrate` 与 migration 事件的 lock/apply——`migrate` 是包含后者的嵌套
区间，相加会重复计数。migration 事件也可能独立出现，不要仅凭 PID 或 identity
把 fixture 行和 migration 行强行 join。任何跨调用、跨并发聚合的相位耗时之和都
不等于墙钟加速比。这里统计的只是写出计时行的调用数，不是测试总数。

仅使用标准库。
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

# 顶层元数据键集合：fixture 与 migration 必须完全一致，不允许缺、不允许多。
METADATA_KEYS = frozenset(
    {
        "version",
        "event",
        "binary_name",
        "test_identity",
        "pid",
        "database_mode",
        "outcome",
        "phases_ms",
    }
)

EVENTS = frozenset({"fixture", "migration"})
OUTCOMES = frozenset({"ok", "error"})

# 相位顺序同时决定报告里的行顺序。
FIXTURE_PHASES = (
    "bootstrap_connection",
    "drop_create_schema",
    "pool_connect",
    "migrate",
    "sequence_reset",
)
MIGRATION_PHASES = ("migration_lock_wait_ms", "migration_apply_ms")

FIXTURE_PHASE_NAMES = frozenset(FIXTURE_PHASES)
MIGRATION_PHASE_NAMES = frozenset(MIGRATION_PHASES)

U32_MAX = 0xFFFFFFFF


class InvalidInput(Exception):
    """输入不满足契约。消息只包含静态原因和行号，绝不携带字段值。"""


def _reject_constant(_token: str) -> None:
    # json.loads 默认把 NaN / Infinity / -Infinity 解析成 float；契约不允许。
    raise ValueError("non-finite number")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    # object_pairs_hook 会作用于任意层级，重复键一律拒绝（不静默后者覆盖前者）。
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen.add(key)
    return dict(pairs)


def _phase_ms(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidInput("phase duration is not a number")
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        raise InvalidInput("phase duration is not representable") from None
    if not math.isfinite(numeric) or numeric < 0:
        raise InvalidInput("phase duration is not a finite nonnegative number")
    return numeric


def _label(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput("metadata label is empty")
    return value


def validate_record(record: object) -> dict:
    """校验单条记录，返回报告内部使用的精简结构。"""
    if not isinstance(record, dict):
        raise InvalidInput("record is not a JSON object")
    if set(record) != METADATA_KEYS:
        raise InvalidInput("record field set does not match the contract")

    version = record["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise InvalidInput("unsupported record version")

    event = record["event"]
    if not isinstance(event, str) or event not in EVENTS:
        raise InvalidInput("unknown event type")

    _label(record["binary_name"])
    _label(record["test_identity"])

    pid = record["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= U32_MAX:
        raise InvalidInput("pid is not a positive u32")

    if record["database_mode"] != "schema":
        raise InvalidInput("unsupported database mode")

    outcome = record["outcome"]
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise InvalidInput("unknown outcome")

    raw_phases = record["phases_ms"]
    if not isinstance(raw_phases, dict):
        raise InvalidInput("phases_ms is not a JSON object")

    phases: dict[str, float] = {}
    for name, value in raw_phases.items():
        if not isinstance(name, str) or name not in (
            FIXTURE_PHASE_NAMES | MIGRATION_PHASE_NAMES
        ):
            raise InvalidInput("unknown phase name")
        phases[name] = _phase_ms(value)

    if event == "fixture":
        if not set(phases) <= FIXTURE_PHASE_NAMES:
            raise InvalidInput("phase is not valid for fixture events")
        if outcome == "ok" and set(phases) != FIXTURE_PHASE_NAMES:
            raise InvalidInput("successful fixture is missing required phases")
    else:
        if not set(phases) <= MIGRATION_PHASE_NAMES:
            raise InvalidInput("phase is not valid for migration events")
        if outcome == "ok" and set(phases) != MIGRATION_PHASE_NAMES:
            raise InvalidInput("successful migration is missing required phases")
        if "migration_apply_ms" in phases and "migration_lock_wait_ms" not in phases:
            raise InvalidInput("migration apply recorded without lock wait")

    return {"event": event, "outcome": outcome, "phases": phases}


def load_records(path: Path) -> list[dict]:
    """读取并校验整个 JSONL 文件；任何问题都抛 InvalidInput。"""
    try:
        data = path.read_bytes()
    except OSError:
        raise InvalidInput("cannot read input file") from None

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidInput("input is not valid UTF-8") from None

    records: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            # 空白行按契约严格拒绝，不做静默跳过。
            raise InvalidInput(f"blank line at line {line_number}")
        try:
            parsed = json.loads(
                line,
                parse_constant=_reject_constant,
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (ValueError, RecursionError):
            raise InvalidInput(f"invalid JSON at line {line_number}") from None
        records.append(validate_record(parsed))

    if not records:
        raise InvalidInput("input contains no records")
    return records


def nearest_rank(sorted_values: list[float], percentile: float) -> float:
    """最近秩分位数：不插值，返回恰好是某个观测值。"""
    rank = math.ceil(percentile * len(sorted_values))
    index = min(max(rank - 1, 0), len(sorted_values) - 1)
    return sorted_values[index]


def median(sorted_values: list[float]) -> float:
    count = len(sorted_values)
    middle = count // 2
    if count % 2:
        return sorted_values[middle]
    # 中值用 a/2 + b/2，避免 a+b 先把两个接近上限的有限值溢出成 Infinity。
    return sorted_values[middle - 1] / 2 + sorted_values[middle] / 2


def _finite_stat(value: float) -> float:
    """聚合统计（sum/median）一旦溢出为 Infinity 即判非法，拒绝半截报告。"""
    if not math.isfinite(value):
        raise InvalidInput("aggregated statistic is not finite")
    return value


def format_ms(value: float) -> str:
    """毫秒保留 3 位小数，去掉无意义的尾零。"""
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text or "0"


def phase_rows(records: list[dict], order: tuple[str, ...]) -> list[tuple]:
    values: dict[str, list[float]] = {name: [] for name in order}
    for record in records:
        for name, value in record["phases"].items():
            values[name].append(value)

    rows = []
    for name in order:
        if not values[name]:
            continue
        samples = sorted(values[name])
        try:
            total = math.fsum(samples)
        except OverflowError:
            raise InvalidInput("aggregated statistic is not finite") from None
        rows.append(
            (
                name,
                len(samples),
                _finite_stat(total),
                _finite_stat(median(samples)),
                nearest_rank(samples, 0.95),
                samples[-1],
            )
        )
    return rows


def _outcome_counts(records: list[dict]) -> tuple[int, int]:
    ok = sum(1 for record in records if record["outcome"] == "ok")
    return ok, len(records) - ok


_CELL_WIDTHS = (24, 8, 14, 14, 14, 14)


def _format_cells(cells: tuple[str, ...]) -> str:
    """按列宽对齐，并用两个空格分隔，避免超宽数值挤在一起无法解析。"""
    padded = [
        cell.ljust(width) if index == 0 else cell.rjust(width)
        for index, (cell, width) in enumerate(zip(cells, _CELL_WIDTHS))
    ]
    return "  ".join(padded)


def _render_table(title: str, records: list[dict], order: tuple[str, ...]) -> list[str]:
    lines = [f"{title} — {len(records)} record(s)"]
    rows = phase_rows(records, order)
    if not rows:
        lines.append("  (no reached phase)")
        lines.append("")
        return lines

    header = _format_cells(("phase", "count", "sum", "median", "p95", "max"))
    lines.append(header)
    lines.append("-" * len(header))
    for name, count, total, med, p95, maximum in rows:
        lines.append(
            _format_cells(
                (
                    name,
                    str(count),
                    format_ms(total),
                    format_ms(med),
                    format_ms(p95),
                    format_ms(maximum),
                )
            )
        )
    lines.append("")
    return lines


def render(records: list[dict]) -> str:
    fixtures = [record for record in records if record["event"] == "fixture"]
    migrations = [record for record in records if record["event"] == "migration"]
    fixture_ok, fixture_err = _outcome_counts(fixtures)
    migration_ok, migration_err = _outcome_counts(migrations)

    lines: list[str] = []
    lines.append("DB timing report (issue #710 STAGE 0 baseline)")
    lines.append(
        f"Records: {len(records)} total "
        f"(fixture={len(fixtures)}, migration={len(migrations)})"
    )
    lines.append(
        f"Fixture calls: {len(fixtures)} (ok={fixture_ok}, error={fixture_err})"
    )
    lines.append(
        f"Migration calls: {len(migrations)} (ok={migration_ok}, error={migration_err})"
    )
    lines.append("")
    lines.extend(_render_table("Fixture phases (ms)", fixtures, FIXTURE_PHASES))
    lines.extend(_render_table("Migration phases (ms)", migrations, MIGRATION_PHASES))
    lines.append("Caveats:")
    lines.append(
        "- within one fixture the five stages are disjoint and may be summed; a "
        "fixture `migrate` span already contains the migration lock-wait and apply "
        "time, so adding those migration spans to it would double count."
    )
    lines.append(
        "- migration events can be standalone; do not join fixture rows and migration "
        "rows solely by PID or test identity."
    )
    lines.append(
        "- no aggregate of stage durations across calls or concurrently running tests "
        "implies wall-clock speedup."
    )
    lines.append(
        "- counts here are fixture/migration invocations that emitted timing rows, "
        "not the total number of tests; read total tests/failures/wall-clock time "
        "from the test logs and CI step durations."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="db_timing_report.py",
        description="Validate and summarize the issue #710 database timing JSONL file",
    )
    parser.add_argument("path", type=Path, help="JSONL timing file to report on")
    args = parser.parse_args(argv)

    try:
        records = load_records(args.path)
        # render 的聚合统计也可能溢出；必须在写任何 stdout 之前捕获。
        output = render(records)
    except InvalidInput as error:
        # 只输出静态原因（可能带行号），不回显原始输入。
        print(f"db_timing_report: invalid timing input ({error})", file=sys.stderr)
        return 1

    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
