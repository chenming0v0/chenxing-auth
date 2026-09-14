"""test_sh/merge_lcov.py 的契约测试（issue #710 转向）。

只用标准库，直接 import 被测模块，不调用 Rust/Cargo，也不依赖 CI。
覆盖：解析形状校验、合并语义（逐行取最大值）、LF/LH 重算、门槛判定、
分片数量校验，以及「真实 llvm-cov 的 LF 可以大于 DA 条数」这一实测口径。
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "merge_lcov.py"
sys.path.insert(0, str(SCRIPT.parent))
import merge_lcov as module  # noqa: E402


def record(source: str, lines: dict[int, int], *, extra: str = "") -> str:
    """构造一条规范 lcov 记录。LF/LH 由 DA 派生，和真实工具不一致时由调用方补充。"""
    da = "".join(f"DA:{line_no},{hits}\n" for line_no, hits in lines.items())
    lf = len(lines)
    lh = sum(1 for hits in lines.values() if hits > 0)
    return f"SF:{source}\n{extra}{da}LF:{lf}\nLH:{lh}\nend_of_record\n"


class ParseTest(unittest.TestCase):
    def test_parses_a_minimal_record(self) -> None:
        files = module.parse_lcov(record("src/a.rs", {1: 1, 2: 0}))
        self.assertEqual(list(files), ["src/a.rs"])
        self.assertEqual(files["src/a.rs"].lines, {1: 1, 2: 0})

    def test_accepts_lf_greater_than_da_count(self) -> None:
        # 实测：真实 llvm-cov 的 lcov 里 LF 会包含没有 DA 记录的行，所以
        # LF 与 DA 条数不相等是合法输入，不能据此报错。
        text = "SF:src/a.rs\nDA:1,1\nLF:5\nLH:1\nend_of_record\n"
        files = module.parse_lcov(text)
        self.assertEqual(files["src/a.rs"].lines, {1: 1})

    def test_rejects_missing_lf_or_lh(self) -> None:
        for name in ("LF", "LH"):
            with self.subTest(missing=name):
                text = "SF:src/a.rs\nDA:1,1\n" + (
                    "LH:1\n" if name == "LF" else "LF:1\n"
                ) + "end_of_record\n"
                with self.assertRaises(module.LcovError):
                    module.parse_lcov(text)

    def test_rejects_duplicate_da_line(self) -> None:
        text = "SF:src/a.rs\nDA:1,1\nDA:1,2\nLF:1\nLH:1\nend_of_record\n"
        with self.assertRaises(module.LcovError):
            module.parse_lcov(text)

    def test_rejects_unknown_directive(self) -> None:
        text = "SF:src/a.rs\nDA:1,1\nLF:1\nLH:1\nZZ:1\nend_of_record\n"
        with self.assertRaises(module.LcovError):
            module.parse_lcov(text)

    def test_rejects_unterminated_record(self) -> None:
        with self.assertRaises(module.LcovError):
            module.parse_lcov("SF:src/a.rs\nDA:1,1\nLF:1\nLH:1\n")

    def test_rejects_empty_input(self) -> None:
        with self.assertRaises(module.LcovError):
            module.parse_lcov("")

    def test_parses_branch_records(self) -> None:
        text = (
            "SF:src/a.rs\n"
            "DA:1,1\n"
            "BRDA:1,0,0,3\n"
            "BRDA:1,0,1,-\n"
            "LF:1\nLH:1\nBRF:2\nBRH:1\n"
            "end_of_record\n"
        )
        files = module.parse_lcov(text)
        branches = files["src/a.rs"].branches
        self.assertEqual(branches[(1, 0, 0)], "3")
        self.assertEqual(branches[(1, 0, 1)], module.NOT_EXECUTED)

    def test_rejects_duplicate_sf_record(self) -> None:
        text = record("src/a.rs", {1: 1}) + record("src/a.rs", {1: 0})
        with self.assertRaises(module.LcovError):
            module.parse_lcov(text)


class MergeTest(unittest.TestCase):
    def test_takes_the_maximum_hit_count_per_line(self) -> None:
        first = module.parse_lcov(record("src/a.rs", {1: 0, 2: 5, 3: 0}))
        second = module.parse_lcov(record("src/a.rs", {1: 1, 2: 0, 3: 0}))
        merged = module.merge([first, second])
        self.assertEqual(merged["src/a.rs"].lines, {1: 1, 2: 5, 3: 0})

    def test_union_of_files_across_shards(self) -> None:
        # 某个文件只在一个分片里出现（其它分片整份零命中而被省略）时，合并结果仍
        # 必须包含它，否则覆盖率会因缺文件而虚假变高。
        first = module.parse_lcov(record("src/a.rs", {1: 1}))
        second = module.parse_lcov(record("src/b.rs", {9: 1}))
        merged = module.merge([first, second])
        self.assertEqual(sorted(merged), ["src/a.rs", "src/b.rs"])
        found, hit = module.total_lines(merged)
        self.assertEqual((found, hit), (2, 2))

    def test_hit_in_any_shard_counts_as_covered(self) -> None:
        first = module.parse_lcov(record("src/a.rs", {1: 0}))
        second = module.parse_lcov(record("src/a.rs", {1: 1}))
        merged = module.merge([first, second])
        self.assertEqual(module.coverage_percent(merged), 100.0)

    def test_no_shards_is_an_error(self) -> None:
        with self.assertRaises(module.LcovError):
            module.merge([])

    def test_branch_union_ignores_not_executed(self) -> None:
        first = module.parse_lcov(
            "SF:src/a.rs\nDA:1,1\nBRDA:1,0,0,-\nLF:1\nLH:1\nend_of_record\n"
        )
        second = module.parse_lcov(
            "SF:src/a.rs\nDA:1,1\nBRDA:1,0,0,2\nLF:1\nLH:1\nend_of_record\n"
        )
        merged = module.merge([first, second])
        self.assertEqual(merged["src/a.rs"].branches[(1, 0, 0)], "2")

    def test_recomputes_derived_totals(self) -> None:
        first = module.parse_lcov(record("src/a.rs", {1: 0, 2: 0}))
        second = module.parse_lcov(record("src/a.rs", {1: 1, 2: 0}))
        merged = module.merge([first, second])
        rendered = module.render(merged)
        self.assertIn("LF:2", rendered)
        self.assertIn("LH:1", rendered)


class RenderAndThresholdTest(unittest.TestCase):
    def test_render_is_deterministic_and_parseable(self) -> None:
        merged = module.merge(
            [
                module.parse_lcov(record("src/b.rs", {2: 1})),
                module.parse_lcov(record("src/a.rs", {1: 1})),
            ]
        )
        rendered = module.render(merged)
        # sorted by source, and the output round-trips through the parser.
        self.assertLess(rendered.index("SF:src/a.rs"), rendered.index("SF:src/b.rs"))
        self.assertEqual(
            sorted(module.parse_lcov(rendered)), ["src/a.rs", "src/b.rs"]
        )

    def test_coverage_percent_of_empty_merged_data_is_an_error(self) -> None:
        with self.assertRaises(module.LcovError):
            module.coverage_percent({})

    def test_main_accepts_when_above_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            inputs = []
            for index, hits in enumerate((1, 1), start=1):
                path = tmp_path / f"shard{index}.info"
                path.write_text(record("src/a.rs", {1: hits}), encoding="utf-8")
                inputs.append(str(path))
            output = tmp_path / "merged.info"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    *inputs,
                    "--output",
                    str(output),
                    "--fail-under-lines",
                    "75",
                    "--expect-shards",
                    "2",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("100.00%", result.stdout)
            self.assertTrue(output.is_file())

    def test_main_fails_below_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            path = tmp_path / "shard1.info"
            path.write_text(record("src/a.rs", {1: 1, 2: 0, 3: 0, 4: 0}), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(path),
                    "--output",
                    str(tmp_path / "merged.info"),
                    "--fail-under-lines",
                    "75",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("below", result.stderr)

    def test_main_fails_when_a_shard_is_missing(self) -> None:
        # 分片缺失时必须失败：用部分数据算出的行覆盖率会偏高，误绿比误红更危险。
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            path = tmp_path / "shard1.info"
            path.write_text(record("src/a.rs", {1: 1}), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(path),
                    "--output",
                    str(tmp_path / "merged.info"),
                    "--expect-shards",
                    "4",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("expected 4 shard inputs", result.stderr)

    def test_main_rejects_malformed_input_without_echoing_record_bodies(self) -> None:
        # 诊断必须能定位到出错的文件（否则多个分片里无从下手），但不得回显记录体
        # 本身——错误信息只包含源文件路径这类已在仓库和 CI 日志中公开的定位信息。
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            path = tmp_path / "shard1.info"
            path.write_text(
                "SF:src/broken.rs\nDA:1,1\nDA:notanumber,2\nend_of_record\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path), "--output", str(tmp_path / "o.info")],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("src/broken.rs", result.stderr)
            self.assertNotIn("notanumber", result.stderr)
            self.assertNotIn("DA:1,1", result.stderr)


if __name__ == "__main__":
    unittest.main()
