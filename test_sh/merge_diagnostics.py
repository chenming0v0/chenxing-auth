#!/usr/bin/env python3
"""Merge per-shard issue #710 diagnostics into one full-suite view.

issue #710 转向：Rust 套件按 PostgreSQL 实例分片后，每个分片只产出**本分片**的
`db-timing.jsonl` 与 `junit.xml`。固定候选关联（`db_timing_junit.compare`）要求每个
候选在整份 JUnit 中恰好出现一次，所以必须先把各分片合成一份完整视图，否则单看
任一分片都会判定「候选缺失」。

输入布局：`<root>` 下递归查找名为 `db-timing.jsonl` 与 `junit.xml` 的文件。
`actions/upload-artifact` 会保留文件上传时的相对路径，而 `download-artifact` 又会按
artifact 名建子目录，所以真实落点形如
`<root>/test-diagnostics-shard-1/_temp/db-timing.jsonl` 与
`<root>/test-diagnostics-shard-1/<owner>/<repo>/target/nextest/default/junit.xml`。
按文件名递归查找，不假设任何中间层级。

输出：
- `db-timing.jsonl`：各分片的记录按文件路径排序后拼接；每条记录先解析 JSON 校验，
  空白行被丢弃（报告对空行是严格拒绝的）。
- `junit.xml`：各分片 JUnit 的 `<testsuite>` 合并到一个 `<testsuites>` 根下，
  由 `merge_junit.merge` 完成。
- `junit-inputs.txt`：参与合并的 JUnit 路径，按路径排序，便于复现。

按路径排序保证合并结果确定；缺失的输入视为该分片没有产出。至少要有 timing 记录和
JUnit，否则失败——静默产出半份数据再据以计算，比直接失败危险得多。

只用标准库。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TIMING_FILENAME = "db-timing.jsonl"
JUNIT_FILENAME = "junit.xml"

# 与 test_sh/merge_junit.py 同目录，直接 import 复用合并逻辑。
sys.path.insert(0, str(Path(__file__).resolve().parent))
import merge_junit  # noqa: E402


class MergeDiagnosticsError(Exception):
    """输入不满足合并契约。消息不含文件内容。"""


def _find(root: Path, filename: str) -> list[Path]:
    """递归查找指定文件名，按路径排序，保证合并结果确定。"""
    return sorted(
        (path for path in root.rglob(filename) if path.is_file()),
        key=lambda path: str(path),
    )


def merge_diagnostics(root: Path, output_dir: Path) -> tuple[int, list[Path]]:
    """合并 root 下各分片的诊断，返回 (记录数, JUnit 输入列表)。"""
    if not root.is_dir():
        raise MergeDiagnosticsError("diagnostics root is not a directory")

    timing_files = _find(root, TIMING_FILENAME)
    if not timing_files:
        raise MergeDiagnosticsError(f"no {TIMING_FILENAME} files found")

    records: list[str] = []
    for timing in timing_files:
        for line in timing.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                json.loads(line)
            except ValueError:
                raise MergeDiagnosticsError(
                    f"invalid JSONL record in {timing.parent.name}"
                ) from None
            records.append(line)

    if not records:
        raise MergeDiagnosticsError("no shard timing records found")

    junits = _find(root, JUNIT_FILENAME)
    if not junits:
        raise MergeDiagnosticsError(f"no {JUNIT_FILENAME} files found")

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / TIMING_FILENAME).write_text(
        "\n".join(records) + "\n", encoding="utf-8"
    )

    merged = merge_junit.merge(junits)
    merge_junit.write(merged, output_dir / JUNIT_FILENAME)
    (output_dir / "junit-inputs.txt").write_text(
        "\n".join(str(path) for path in junits) + "\n", encoding="utf-8"
    )
    return len(records), junits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        count, junits = merge_diagnostics(args.root, args.output_dir)
    except (OSError, MergeDiagnosticsError, merge_junit.MergeJunitError) as error:
        print(f"merge_diagnostics: {error}", file=sys.stderr)
        return 1

    print(
        f"merge_diagnostics: {count} timing records from "
        f"{len(junits)} shard JUnit files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
