#!/usr/bin/env python3
"""辰星认证中枢 - 数据库计时 JSONL 报告器（issue #710）。

用法：

    python3 test_sh/db_timing_report.py PATH [--junit PATH]

`PATH` 是测试进程（或模板构建示例）写出的 JSONL 文件。每一行是一个 JSON
对象。本脚本先校验**整个**文件，全部合法才打印报告；任何一行不合法都会以非零
退出，并且不打印部分报告、不回显原始输入或其中的敏感字段/错误文本。

支持两代 schema，二者互不影响：

- v1 `database_mode="schema"`：
  - `fixture` 成功时 `phases_ms` 恰好包含 bootstrap_connection、
    drop_create_schema、pool_connect、migrate、sequence_reset 五个相位；
    固定 ID 用例跳过 sequence_reset 记 0。失败时允许只包含已到达的相位。
  - `migration` 成功时恰好包含 migration_lock_wait_ms 和 migration_apply_ms；
    失败时允许缺失，但 apply 存在则 lock 必须存在。
- v2 `database_mode="template"`：
  - `fixture`（模板克隆）带额外顶层 `fixture_total_ms`，成功时 `phases_ms` 恰好
    包含 bootstrap_connection、database_clone_ms、pool_connect、sequence_reset；
    失败时允许子集。
  - `template_prepare`（模板构建）没有 `fixture_total_ms`，成功时 `phases_ms`
    恰好是 `template_prepare_ms`；失败时允许子集（甚至为空）。

两代都拒绝：空/空白行、JSON 截断、重复键、布尔冒充数字、NaN/Infinity、负时长、
未知事件/相位、缺失必需相位、多余字段；聚合统计（sum/median）溢出为非有限值也
判为非法，不打印半截报告。

报告按 `(version, event)` 分组：schema fixture、schema migration、template
fixture、template prepare。`fixture_total_ms` 是模板克隆的包裹计时，已包含四个
互不重叠的阶段；`template_prepare_ms` 是独立的模板构建计时，其内部迁移事件被
suppress，因此 migration 计数不代表每一次 migrate 调用。跨事件、跨并发的耗时
相加都不等于墙钟加速比。这里统计的是写出计时行的调用数，不是测试总数。

`--junit PATH` 时额外做 stage 1 的两个候选用例关联对比，详见
`db_timing_junit.py`。

仅使用标准库。
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import db_timing_junit

# 两代 schema 共同的元数据键（不含 v2 模板 fixture 的 fixture_total_ms）。
BASE_METADATA_KEYS = frozenset(
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
V2_TEMPLATE_FIXTURE_KEYS = BASE_METADATA_KEYS | {"fixture_total_ms"}

OUTCOMES = frozenset({"ok", "error"})

# v1 schema 相位（顺序即报告行顺序）。
V1_FIXTURE_PHASES = (
    "bootstrap_connection",
    "drop_create_schema",
    "pool_connect",
    "migrate",
    "sequence_reset",
)
V1_MIGRATION_PHASES = ("migration_lock_wait_ms", "migration_apply_ms")

# v2 template 相位。
V2_TEMPLATE_FIXTURE_PHASES = (
    "bootstrap_connection",
    "database_clone_ms",
    "pool_connect",
    "sequence_reset",
)
V2_TEMPLATE_PREPARE_PHASES = ("template_prepare_ms",)

V1_FIXTURE_PHASE_NAMES = frozenset(V1_FIXTURE_PHASES)
V1_MIGRATION_PHASE_NAMES = frozenset(V1_MIGRATION_PHASES)
V2_TEMPLATE_FIXTURE_PHASE_NAMES = frozenset(V2_TEMPLATE_FIXTURE_PHASES)
V2_TEMPLATE_PREPARE_PHASE_NAMES = frozenset(V2_TEMPLATE_PREPARE_PHASES)

ALL_PHASE_NAMES = (
    V1_FIXTURE_PHASE_NAMES
    | V1_MIGRATION_PHASE_NAMES
    | V2_TEMPLATE_FIXTURE_PHASE_NAMES
    | V2_TEMPLATE_PREPARE_PHASE_NAMES
)

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


def _duration_ms(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidInput("duration is not a number")
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        raise InvalidInput("duration is not representable") from None
    if not math.isfinite(numeric) or numeric < 0:
        raise InvalidInput("duration is not a finite nonnegative number")
    return numeric


def _label(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput("metadata label is empty")
    return value


def _parse_phases(raw_phases: object) -> dict[str, float]:
    if not isinstance(raw_phases, dict):
        raise InvalidInput("phases_ms is not a JSON object")
    phases: dict[str, float] = {}
    for name, value in raw_phases.items():
        if not isinstance(name, str) or name not in ALL_PHASE_NAMES:
            raise InvalidInput("unknown phase name")
        phases[name] = _duration_ms(value)
    return phases


def _validate_v1(record: dict) -> dict:
    if set(record) != BASE_METADATA_KEYS:
        raise InvalidInput("record field set does not match the v1 contract")
    if record["database_mode"] != "schema":
        raise InvalidInput("v1 record has an unsupported database mode")

    event = record["event"]
    if event not in ("fixture", "migration"):
        raise InvalidInput("unknown v1 event type")
    outcome = _outcome(record)
    phases = _parse_phases(record["phases_ms"])

    if event == "fixture":
        if not set(phases) <= V1_FIXTURE_PHASE_NAMES:
            raise InvalidInput("phase is not valid for a v1 fixture")
        if outcome == "ok" and set(phases) != V1_FIXTURE_PHASE_NAMES:
            raise InvalidInput("successful v1 fixture is missing required phases")
    else:
        if not set(phases) <= V1_MIGRATION_PHASE_NAMES:
            raise InvalidInput("phase is not valid for a v1 migration")
        if outcome == "ok" and set(phases) != V1_MIGRATION_PHASE_NAMES:
            raise InvalidInput("successful v1 migration is missing required phases")
        if "migration_apply_ms" in phases and "migration_lock_wait_ms" not in phases:
            raise InvalidInput("migration apply recorded without lock wait")

    return _record(record, 1, event, "schema", outcome, phases, None)


def _validate_v2(record: dict) -> dict:
    if record.get("database_mode") != "template":
        raise InvalidInput("v2 record has an unsupported database mode")

    event = record.get("event")
    outcome = _outcome(record)

    if event == "fixture":
        if set(record) != V2_TEMPLATE_FIXTURE_KEYS:
            raise InvalidInput("record field set does not match the v2 template fixture")
        phases = _parse_phases(record["phases_ms"])
        if not set(phases) <= V2_TEMPLATE_FIXTURE_PHASE_NAMES:
            raise InvalidInput("phase is not valid for a v2 template fixture")
        if outcome == "ok" and set(phases) != V2_TEMPLATE_FIXTURE_PHASE_NAMES:
            raise InvalidInput("successful template fixture is missing required phases")
        total = _duration_ms(record["fixture_total_ms"])
        return _record(record, 2, event, "template", outcome, phases, total)

    if event == "template_prepare":
        if set(record) != BASE_METADATA_KEYS:
            raise InvalidInput("record field set does not match the v2 template_prepare")
        phases = _parse_phases(record["phases_ms"])
        if not set(phases) <= V2_TEMPLATE_PREPARE_PHASE_NAMES:
            raise InvalidInput("phase is not valid for template_prepare")
        if outcome == "ok" and set(phases) != V2_TEMPLATE_PREPARE_PHASE_NAMES:
            raise InvalidInput("successful template_prepare is missing template_prepare_ms")
        return _record(record, 2, event, "template", outcome, phases, None)

    raise InvalidInput("unknown v2 event type")


def _outcome(record: dict) -> str:
    outcome = record.get("outcome")
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise InvalidInput("unknown outcome")
    return outcome


def _record(
    record: dict,
    version: int,
    event: str,
    database_mode: str,
    outcome: str,
    phases: dict[str, float],
    fixture_total_ms: float | None,
) -> dict:
    _label(record["binary_name"])
    _label(record["test_identity"])
    pid = record["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= U32_MAX:
        raise InvalidInput("pid is not a positive u32")
    return {
        "version": version,
        "event": event,
        "database_mode": database_mode,
        "outcome": outcome,
        "phases": phases,
        "fixture_total_ms": fixture_total_ms,
        "binary_name": record["binary_name"],
        "test_identity": record["test_identity"],
        "pid": pid,
    }


def validate_record(record: object) -> dict:
    """校验单条记录，返回报告内部使用的精简结构。"""
    if not isinstance(record, dict):
        raise InvalidInput("record is not a JSON object")

    version = record.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise InvalidInput("unsupported record version")
    if version == 1:
        return _validate_v1(record)
    if version == 2:
        return _validate_v2(record)
    raise InvalidInput("unsupported record version")


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


def _safe_sum(samples: list[float]) -> float:
    try:
        total = math.fsum(samples)
    except OverflowError:
        raise InvalidInput("aggregated statistic is not finite") from None
    return _finite_stat(total)


def format_ms(value: float) -> str:
    """毫秒保留 3 位小数，去掉无意义的尾零。"""
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text or "0"


def stats_rows(samples_by_name: dict[str, list[float]], order: tuple[str, ...]) -> list[tuple]:
    rows = []
    for name in order:
        if not samples_by_name[name]:
            continue
        samples = sorted(samples_by_name[name])
        rows.append(
            (
                name,
                len(samples),
                _safe_sum(samples),
                _finite_stat(median(samples)),
                nearest_rank(samples, 0.95),
                samples[-1],
            )
        )
    return rows


def phase_rows(records: list[dict], order: tuple[str, ...]) -> list[tuple]:
    values: dict[str, list[float]] = {name: [] for name in order}
    for record in records:
        for name, value in record["phases"].items():
            if name in values:
                values[name].append(value)
    return stats_rows(values, order)


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


def _render_rows(title: str, rows: list[tuple]) -> list[str]:
    lines = [title]
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


def _render_table(title: str, records: list[dict], order: tuple[str, ...]) -> list[str]:
    ok, error = _outcome_counts(records)
    heading = f"{title} — {len(records)} record(s), ok={ok}, error={error}"
    return _render_rows(heading, phase_rows(records, order))


def _template_total_rows(records: list[dict]) -> list[tuple]:
    values = [record["fixture_total_ms"] for record in records]
    samples = [value for value in values if value is not None]
    return stats_rows({"fixture_total_ms": samples}, ("fixture_total_ms",))


def _cost_summary(records: list[dict]) -> list[str]:
    lines: list[str] = []
    clone = [
        record["phases"]["database_clone_ms"]
        for record in records
        if record["version"] == 2
        and record["event"] == "fixture"
        and "database_clone_ms" in record["phases"]
    ]
    total = [
        record["fixture_total_ms"]
        for record in records
        if record["version"] == 2
        and record["event"] == "fixture"
        and record["fixture_total_ms"] is not None
    ]
    prepare = [
        record["phases"]["template_prepare_ms"]
        for record in records
        if record["version"] == 2
        and record["event"] == "template_prepare"
        and "template_prepare_ms" in record["phases"]
    ]
    if not (clone or total or prepare):
        return lines

    lines.append("Template cost visibility (ms; not additive across events):")
    if clone:
        lines.append(
            f"  database_clone_ms       count={len(clone):<6} sum={format_ms(_safe_sum(clone))}"
        )
    if total:
        lines.append(
            f"  fixture_total_ms        count={len(total):<6} sum={format_ms(_safe_sum(total))}"
        )
    if prepare:
        lines.append(
            f"  template_prepare_ms     count={len(prepare):<6} sum={format_ms(_safe_sum(prepare))}"
        )
    lines.append("")
    return lines


_GROUPS = (
    ("Schema fixture (v1)", 1, "fixture", V1_FIXTURE_PHASES),
    ("Schema migration (v1)", 1, "migration", V1_MIGRATION_PHASES),
    ("Template fixture (v2)", 2, "fixture", V2_TEMPLATE_FIXTURE_PHASES),
    ("Template prepare (v2)", 2, "template_prepare", V2_TEMPLATE_PREPARE_PHASES),
)

_CAVEATS = (
    "Caveats:",
    "- v1: within one schema fixture the five stages are disjoint and may be summed; "
    "the fixture `migrate` stage already contains migration lock-wait and apply time, "
    "so adding those migration events to it would double count.",
    "- v2: the four template fixture stages are disjoint and may be summed, but "
    "`fixture_total_ms` is the wrapper timer that already contains them plus "
    "interstage overhead; do not add clone stages to it.",
    "- v2: `template_prepare_ms` is a separate template build; its inner migration "
    "diagnostic is suppressed, so migration counts here are not every migrate call.",
    "- migration events can be standalone; do not join fixture rows and migration rows "
    "solely by PID or test identity.",
    "- no aggregate of stage durations across calls or concurrently running tests "
    "implies wall-clock speedup.",
    "- counts here are fixture/migration/prepare invocations that emitted timing rows, "
    "not the total number of tests; standalone migration errors are not failed tests. "
    "Read total tests/failures/wall-clock time from the test logs and CI step durations.",
)


def render(records: list[dict]) -> str:
    lines: list[str] = []
    lines.append("DB timing report (issue #710 STAGE 1)")
    counts = {}
    for _title, version, event, _order in _GROUPS:
        counts[(version, event)] = sum(
            1 for record in records if record["version"] == version and record["event"] == event
        )
    lines.append(
        f"Records: {len(records)} total "
        f"(schema_fixture={counts[(1, 'fixture')]}, "
        f"schema_migration={counts[(1, 'migration')]}, "
        f"template_fixture={counts[(2, 'fixture')]}, "
        f"template_prepare={counts[(2, 'template_prepare')]})"
    )
    lines.append("")

    for title, version, event, order in _GROUPS:
        selected = [
            record
            for record in records
            if record["version"] == version and record["event"] == event
        ]
        lines.extend(_render_table(title, selected, order))
        if version == 2 and event == "fixture":
            lines.extend(
                _render_rows("Template fixture overall (v2)", _template_total_rows(selected))
            )

    lines.extend(_cost_summary(records))
    lines.extend(_CAVEATS)
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="db_timing_report.py",
        description="Validate and summarize the issue #710 database timing JSONL file",
    )
    parser.add_argument("path", type=Path, help="JSONL timing file to report on")
    parser.add_argument(
        "--junit",
        type=Path,
        default=None,
        help="optional nextest JUnit XML for the two stage 1 candidate comparisons",
    )
    args = parser.parse_args(argv)

    try:
        records = load_records(args.path)
        # render/compare 的聚合统计也可能溢出；必须在写任何 stdout 之前捕获。
        output = render(records)
        if args.junit is not None:
            output += "\n".join(db_timing_junit.compare(records, args.junit))
    except (InvalidInput, db_timing_junit.JunitError) as error:
        # 只输出静态原因（可能带行号），不回显原始输入。
        print(f"db_timing_report: invalid timing input ({error})", file=sys.stderr)
        return 1

    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
