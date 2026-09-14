"""test_sh/merge_junit.py 与 test_sh/merge_diagnostics.py 的契约测试（issue #710）。

只用标准库，直接 import 被测模块，不调用 Rust/Cargo，也不依赖 CI。
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import merge_diagnostics as diagnostics  # noqa: E402
import merge_junit as junit  # noqa: E402

JUNIT_SCRIPT = HERE / "merge_junit.py"
DIAGNOSTICS_SCRIPT = HERE / "merge_diagnostics.py"


def junit_file(tests: list[tuple[str, str, str]]) -> str:
    """构造一个 nextest 形状的 JUnit：testsuite + testcase(name, classname, time)。"""
    cases = "".join(
        f'<testcase name="{name}" classname="{classname}" time="{elapsed}"/>'
        for name, classname, elapsed in tests
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="nextest-run"><testsuite name="chenxing-auth">{cases}'
        "</testsuite></testsuites>"
    )


class MergeJunitTest(unittest.TestCase):
    def test_merges_suites_under_one_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            first = tmp_path / "a.xml"
            second = tmp_path / "b.xml"
            first.write_text(junit_file([("t1", "chenxing-auth", "1.0")]), encoding="utf-8")
            second.write_text(junit_file([("t2", "chenxing-auth", "2.0")]), encoding="utf-8")

            merged = junit.merge([first, second])
            self.assertEqual(merged.tag, "testsuites")
            self.assertEqual(merged.get("tests"), "2")
            names = [case.get("name") for case in merged.iter("testcase")]
            self.assertEqual(names, ["t1", "t2"])

    def test_accepts_a_bare_testsuite_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.xml"
            path.write_text(
                '<testsuite name="s"><testcase name="t" classname="c" time="1.0"/>'
                "</testsuite>",
                encoding="utf-8",
            )
            merged = junit.merge([path])
            self.assertEqual(merged.get("tests"), "1")

    def test_rejects_unparseable_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.xml"
            path.write_text("<not-closed", encoding="utf-8")
            with self.assertRaises(junit.MergeJunitError):
                junit.merge([path])

    def test_rejects_input_without_testcases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.xml"
            path.write_text('<testsuites name="x"><testsuite name="s"/></testsuites>', encoding="utf-8")
            with self.assertRaises(junit.MergeJunitError):
                junit.merge([path])

    def test_rejects_empty_input_list(self) -> None:
        with self.assertRaises(junit.MergeJunitError):
            junit.merge([])

    def test_cli_writes_a_parseable_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            first = tmp_path / "a.xml"
            first.write_text(junit_file([("t1", "chenxing-auth", "1.0")]), encoding="utf-8")
            output = tmp_path / "merged.xml"
            result = subprocess.run(
                [sys.executable, str(JUNIT_SCRIPT), str(first), "--output", str(output)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = ET.parse(output).getroot()
            self.assertEqual(len(root.findall(".//testcase")), 1)


class MergeDiagnosticsTest(unittest.TestCase):
    def _shard(self, root: Path, name: str, records: list[str], *, junit_text: str | None) -> None:
        directory = root / name
        directory.mkdir(parents=True)
        (directory / "db-timing.jsonl").write_text(
            "\n".join(records) + "\n", encoding="utf-8"
        )
        if junit_text is not None:
            (directory / "junit.xml").write_text(junit_text, encoding="utf-8")

    def test_concatenates_records_and_merges_junit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "shards"
            self._shard(
                root, "s2", ['{"version": 1, "event": "fixture"}'],
                junit_text=junit_file([("t2", "chenxing-auth", "2.0")]),
            )
            self._shard(
                root, "s1", ['{"version": 1, "event": "fixture"}'],
                junit_text=junit_file([("t1", "chenxing-auth", "1.0")]),
            )
            out = tmp_path / "merged"

            count, junits = diagnostics.merge_diagnostics(root, out)
            self.assertEqual(count, 2)
            self.assertEqual([path.parent.name for path in junits], ["s1", "s2"])
            merged = ET.parse(out / "junit.xml").getroot()
            self.assertEqual(
                [case.get("name") for case in merged.iter("testcase")], ["t1", "t2"]
            )
            self.assertTrue((out / "db-timing.jsonl").is_file())

    def test_rejects_invalid_json_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "shards"
            self._shard(
                root, "s1", ["{not json"],
                junit_text=junit_file([("t1", "chenxing-auth", "1.0")]),
            )
            with self.assertRaises(diagnostics.MergeDiagnosticsError):
                diagnostics.merge_diagnostics(root, tmp_path / "merged")

    def test_rejects_when_no_shards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "shards"
            root.mkdir()
            with self.assertRaises(diagnostics.MergeDiagnosticsError):
                diagnostics.merge_diagnostics(root, tmp_path / "merged")

    def test_rejects_when_junit_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "shards"
            self._shard(root, "s1", ['{"version": 1}'], junit_text=None)
            with self.assertRaises(diagnostics.MergeDiagnosticsError):
                diagnostics.merge_diagnostics(root, tmp_path / "merged")

    def test_cli_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "shards"
            self._shard(
                root, "s1", ['{"version": 1, "event": "fixture"}'],
                junit_text=junit_file([("t1", "chenxing-auth", "1.0")]),
            )
            out = tmp_path / "merged"
            result = subprocess.run(
                [
                    sys.executable,
                    str(DIAGNOSTICS_SCRIPT),
                    str(root),
                    "--output-dir",
                    str(out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "junit.xml").is_file())
            self.assertTrue((out / "db-timing.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
