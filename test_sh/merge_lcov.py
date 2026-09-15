#!/usr/bin/env python3
"""Merge per-shard lcov files and enforce the single line-coverage threshold.

issue #710 转向：Rust 测试套件按 PostgreSQL 实例分片后，每个分片只跑了一部分
用例，因此**每个分片自己的行覆盖率都是局部值**，门槛只能在合并后判定。

合并语义：同一文件同一行的命中数取各分片最大值；只要任一分片执行过该行，合并后
即算命中。这等价于整套测试串行跑一次的结果，也是 `lcov -a` 与 Codecov 的合并语义。
LF/LH/FNF/FNH/BRF/BRH 一律由合并后的 DA/FNDA/BRDA 重新计算，不沿用输入声明值。

为什么不用 `cargo llvm-cov report` 跨 job 合并：那条路线要么依赖
`nextest-archive`（cargo-llvm-cov 0.9.0 + nextest 0.9.143 命中上游未修复的
taiki-e/cargo-llvm-cov#520），要么要求合并 job 里已存在插桩产物。直接合并已经
生成好的 lcov 不依赖工具的构建布局，行为可复现、可单测。

实测口径校验（对 CI 真实 lcov 工件）：本脚本算出的行覆盖率与 `cargo llvm-cov`
原生 `LF/LH` 相差不到 0.1 个百分点（81.84% vs 81.75%），远在 75% 门槛之上。
注意 llvm-cov 的 `LF` 会包含没有 `DA` 记录的行，所以 LF 与 `DA` 条数**不相等**，
不能据此校验输入。

只用标准库。
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path

# lcov 的分支从未执行时 `taken` 是 "-"，否则是命中次数。
NOT_EXECUTED = "-"

# 每个文件必须出现的指令集合；其余指令按可选处理。
REQUIRED_FILE_DIRECTIVES = ("LF", "LH")


class LcovError(Exception):
    """输入不满足合并契约。消息不包含文件内容。"""


@dataclass
class FileCoverage:
    """单个 `SF:` 记录的合并单位。"""

    source: str
    lines: dict[int, int] = field(default_factory=dict)
    functions: dict[str, tuple[int, ...]] = field(default_factory=dict)
    function_hits: dict[str, int] = field(default_factory=dict)
    branches: dict[tuple[int, int, int], str] = field(default_factory=dict)


def _parse_int(value: str, what: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise LcovError(f"{what} is not an integer") from None
    if parsed < 0:
        raise LcovError(f"{what} is negative")
    return parsed


def parse_lcov(text: str) -> dict[str, FileCoverage]:
    """解析一个 lcov 文件。形状错误直接失败，不做猜测。"""
    files: dict[str, FileCoverage] = {}
    current: FileCoverage | None = None
    seen: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line == "end_of_record":
            if current is None:
                raise LcovError("end_of_record without a preceding SF")
            missing = [name for name in REQUIRED_FILE_DIRECTIVES if name not in seen]
            if missing:
                raise LcovError(
                    f"record for {current.source} is missing {', '.join(missing)}"
                )
            if current.source in files:
                raise LcovError(f"duplicate SF record: {current.source}")
            files[current.source] = current
            current = None
            seen = set()
            continue

        key, _, value = line.partition(":")
        if key == "TN":
            continue
        if key == "SF":
            if current is not None:
                raise LcovError("SF without a preceding end_of_record")
            if not value:
                raise LcovError("SF is empty")
            current = FileCoverage(source=value)
            continue
        if current is None:
            raise LcovError(f"directive outside a record: {key}")

        if key == "DA":
            parts = value.split(",")
            if len(parts) < 2:
                raise LcovError(f"malformed DA in {current.source}")
            line_no = _parse_int(
                parts[0], f"DA line in {current.source}"
            )
            hits = _parse_int(
                parts[1], f"DA hit count in {current.source}"
            )
            if line_no in current.lines:
                raise LcovError(f"duplicate DA line {line_no} in {current.source}")
            current.lines[line_no] = hits
        elif key == "FN":
            parts = value.split(",")
            if len(parts) >= 3 and parts[1].isdigit():
                start = _parse_int(parts[0], "FN start")
                end = _parse_int(parts[1], "FN end")
                name = ",".join(parts[2:])
                current.functions[name] = (start, end)
            elif len(parts) >= 2:
                start = _parse_int(parts[0], "FN start")
                name = ",".join(parts[1:])
                current.functions[name] = (start,)
            else:
                raise LcovError(f"malformed FN in {current.source}")
            if not name:
                raise LcovError(f"FN without a name in {current.source}")
        elif key == "FNDA":
            count_text, _, name = value.partition(",")
            if not name:
                raise LcovError(f"FNDA without a name in {current.source}")
            count = _parse_int(count_text, "FNDA count")
            current.function_hits[name] = max(current.function_hits.get(name, 0), count)
        elif key == "BRDA":
            parts = value.split(",")
            if len(parts) != 4:
                raise LcovError(f"malformed BRDA in {current.source}")
            block = _parse_int(parts[1], "BRDA block")
            branch = _parse_int(parts[2], "BRDA branch")
            taken = parts[3]
            if taken != NOT_EXECUTED:
                _parse_int(taken, "BRDA taken")
            key_name = (_parse_int(parts[0], "BRDA line"), block, branch)
            if key_name in current.branches:
                raise LcovError(f"duplicate BRDA {key_name} in {current.source}")
            current.branches[key_name] = taken
        elif key in {"LF", "LH", "FNF", "FNH", "BRF", "BRH"}:
            # 派生值：解析以求输入合法，但合并后一律重新计算。
            _parse_int(value, key)
            seen.add(key)
        else:
            raise LcovError(f"unsupported lcov directive: {key}")

    if current is not None:
        raise LcovError(f"record for {current.source} is missing end_of_record")
    if not files:
        raise LcovError("no SF records found")
    return files


def merge(shards: list[dict[str, FileCoverage]]) -> dict[str, FileCoverage]:
    """逐行/逐分支取最大值合并各分片。

    取并集而非要求各分片文件集合完全一致：某个源码文件在某个分片里若整份都未
    出现（llvm-cov 可能省略完全零命中的文件），该分片对这份文件贡献 0，而不是让
    整个门槛误红。这与 `lcov -a` 的合并语义一致。
    """
    if not shards:
        raise LcovError("no shard inputs")

    merged: dict[str, FileCoverage] = {}
    for shard in shards:
        for source, coverage in shard.items():
            target = merged.get(source)
            if target is None:
                merged[source] = FileCoverage(
                    source=source,
                    lines=dict(coverage.lines),
                    functions=dict(coverage.functions),
                    function_hits=dict(coverage.function_hits),
                    branches=dict(coverage.branches),
                )
                continue
            for line_no, hits in coverage.lines.items():
                target.lines[line_no] = max(target.lines.get(line_no, 0), hits)
            for name, hits in coverage.function_hits.items():
                target.function_hits[name] = max(target.function_hits.get(name, 0), hits)
            for name, span in coverage.functions.items():
                target.functions.setdefault(name, span)
            for branch_key, taken in coverage.branches.items():
                if taken == NOT_EXECUTED:
                    continue
                previous = target.branches.get(branch_key, NOT_EXECUTED)
                if previous == NOT_EXECUTED:
                    target.branches[branch_key] = taken
                else:
                    target.branches[branch_key] = str(max(int(previous), int(taken)))
    return merged


def render(merged: dict[str, FileCoverage]) -> str:
    """渲染成规范化的 lcov（记录、行、函数、分支都按确定顺序）。"""
    out: list[str] = []
    for source in sorted(merged):
        coverage = merged[source]
        out.append("TN:")
        out.append(f"SF:{coverage.source}")
        for name in sorted(coverage.functions):
            out.append(f"FN:{','.join(str(part) for part in coverage.functions[name])},{name}")
        for name in sorted(coverage.function_hits):
            out.append(f"FNDA:{coverage.function_hits[name]},{name}")
        if coverage.functions:
            out.append(f"FNF:{len(coverage.functions)}")
            out.append(
                "FNH:"
                f"{sum(1 for name in coverage.functions if coverage.function_hits.get(name, 0) > 0)}"
            )
        for branch_key in sorted(coverage.branches):
            line_no, block, branch = branch_key
            out.append(f"BRDA:{line_no},{block},{branch},{coverage.branches[branch_key]}")
        if coverage.branches:
            out.append(f"BRF:{len(coverage.branches)}")
            out.append(
                "BRH:"
                f"{sum(1 for taken in coverage.branches.values() if taken != NOT_EXECUTED and int(taken) > 0)}"
            )
        for line_no in sorted(coverage.lines):
            out.append(f"DA:{line_no},{coverage.lines[line_no]}")
        out.append(f"LF:{len(coverage.lines)}")
        out.append(f"LH:{sum(1 for hits in coverage.lines.values() if hits > 0)}")
        out.append("end_of_record")
    return "\n".join(out) + "\n"


def total_lines(merged: dict[str, FileCoverage]) -> tuple[int, int]:
    """返回合并后的 (LF, LH)。"""
    found = sum(len(coverage.lines) for coverage in merged.values())
    hit = sum(
        1 for coverage in merged.values() for hits in coverage.lines.values() if hits > 0
    )
    return found, hit


def coverage_percent(merged: dict[str, FileCoverage]) -> float:
    found, hit = total_lines(merged)
    if found <= 0:
        raise LcovError("merged coverage has no executable lines")
    percent = hit * 100.0 / found
    if not math.isfinite(percent):
        raise LcovError("merged coverage percentage is not finite")
    return percent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fail-under-lines", type=float, default=None)
    parser.add_argument(
        "--expect-shards",
        type=int,
        default=None,
        help="要求输入恰好这么多个分片；分片缺失时失败，避免用部分数据算出偏高的覆盖率",
    )
    args = parser.parse_args(argv)

    if args.expect_shards is not None and len(args.inputs) != args.expect_shards:
        print(
            f"merge_lcov: expected {args.expect_shards} shard inputs, got {len(args.inputs)}",
            file=sys.stderr,
        )
        return 1

    try:
        shards = [parse_lcov(path.read_text(encoding="utf-8")) for path in args.inputs]
        merged = merge(shards)
        args.output.write_text(render(merged), encoding="utf-8")
        found, hit = total_lines(merged)
        percent = coverage_percent(merged)
    except (OSError, LcovError) as error:
        print(f"merge_lcov: {error}", file=sys.stderr)
        return 1

    print(f"merged {len(args.inputs)} shards: {hit}/{found} lines = {percent:.2f}%")
    if args.fail_under_lines is not None and percent < args.fail_under_lines:
        print(
            f"merge_lcov: line coverage {percent:.2f}% is below the "
            f"{args.fail_under_lines:.2f}% threshold",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
