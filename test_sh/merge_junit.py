#!/usr/bin/env python3
"""Merge nextest JUnit XML files produced by separate CI shards.

issue #710 转向：Rust 测试套件按 PostgreSQL 实例分片后，每个分片只跑一部分用例，
因此每个分片的 JUnit 只包含**本分片的** testcase。诊断报告里的固定候选用例关联
要求每个候选在整份 JUnit 中恰好出现一次，所以必须先把各分片的 JUnit 合成一份
完整视图再关联。

合并只做一件事：按输入顺序收集所有 `<testsuite>` 元素，写到一个新的
`<testsuites>` 根下。消费者（`db_timing_junit.load_testcases`）只遍历 `testcase`
元素并读取其 `name` / `classname` / `time` 与子元素，不依赖 `testsuite` 的聚合
属性，因此这里不重算也不伪造计数——伪造出来的数字只会误导阅读者。

只用标准库。
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


class MergeJunitError(Exception):
    """输入不是可合并的 nextest JUnit。消息不包含原始 XML。"""


def merge(paths: list[Path]) -> ET.Element:
    """把若干 JUnit 文件合并成一个 `<testsuites>` 根元素。"""
    if not paths:
        raise MergeJunitError("no JUnit inputs")

    merged = ET.Element("testsuites", {"name": "nextest-merged"})
    total = 0
    for path in paths:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            raise MergeJunitError(f"cannot parse JUnit input: {path.name}") from None

        if root.tag == "testsuite":
            suites = [root]
        elif root.tag == "testsuites":
            suites = [child for child in root if child.tag == "testsuite"]
        else:
            raise MergeJunitError(f"unsupported JUnit root tag in {path.name}: {root.tag}")

        if not suites:
            raise MergeJunitError(f"no testsuite elements in {path.name}")
        for suite in suites:
            merged.append(suite)
            total += len(suite.findall("testcase"))

    if total == 0:
        raise MergeJunitError("merged JUnit contains no testcase elements")
    merged.set("tests", str(total))
    return merged


def write(root: ET.Element, path: Path) -> None:
    """把合并后的根元素写成 UTF-8 XML，带 XML 声明。"""
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        merged = merge(args.inputs)
        write(merged, args.output)
    except MergeJunitError as error:
        print(f"merge_junit: {error}", file=sys.stderr)
        return 1

    print(f"merge_junit: merged {len(args.inputs)} files, {merged.get('tests')} testcases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
