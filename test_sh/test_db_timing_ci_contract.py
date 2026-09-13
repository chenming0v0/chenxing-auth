"""issue #710 STAGE 0: static contract assertions for .github/workflows/ci.yml.

This test is stdlib-only: it validates the workflow text with indentation-aware
step blocks instead of pulling in a YAML dependency. It guards the STAGE 0 CI
wiring so a later refactor cannot silently:

- move CHENXING_TEST_DB_TIMING_FILE to job scope or into the coverage job,
- drop the always-run report step or its test-step binding,
- stop uploading the raw timing diagnostics when tests fail,
- touch the coverage gate or its artifact.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"

UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
UPLOAD_REF = f"actions/upload-artifact@{UPLOAD_SHA}"
TIMING_VAR = "CHENXING_TEST_DB_TIMING_FILE"
TIMING_VALUE = "${{ runner.temp }}/db-timing.jsonl"
TEST_STEP_NAME = "Run Rust tests in parallel"


class WorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = CI.read_text(encoding="utf-8").splitlines()

    def block(self, start: int) -> list[str]:
        """Return the step block starting at a `      - ` line."""
        end = len(self.lines)
        for index in range(start + 1, len(self.lines)):
            if self.lines[index].startswith("      - "):
                end = index
                break
        return self.lines[start:end]

    def step_index_by_name(self, name: str) -> int:
        for index, line in enumerate(self.lines):
            if line.startswith("      - ") and line.strip() == f"- name: {name}":
                return index
        self.fail(f"step {name!r} not found")

    def step_index_containing(self, needle: str) -> int:
        for index, line in enumerate(self.lines):
            if needle not in line:
                continue
            for back in range(index, -1, -1):
                if self.lines[back].startswith("      - "):
                    return back
            break
        self.fail(f"no step contains {needle!r}")

    def coverage_start(self) -> int:
        for index, line in enumerate(self.lines):
            if line == "  coverage:":
                return index
        self.fail("coverage job not found")

    def test_timing_variable_is_step_scoped_to_rust_tests(self) -> None:
        occurrences = [i for i, line in enumerate(self.lines) if TIMING_VAR in line]
        self.assertEqual(len(occurrences), 1, "timing variable must appear exactly once")

        timing_index = occurrences[0]
        self.assertEqual(self.lines[timing_index], f"          {TIMING_VAR}: {TIMING_VALUE}")
        # 10-space indent means a step-level `env:` value, never a job-level one
        # (job env values are indented 6 spaces).
        self.assertEqual(len(self.lines[timing_index]) - len(self.lines[timing_index].lstrip()), 10)

        # The nearest enclosing `env:` key must be the 8-space step-level key.
        for index in range(timing_index - 1, -1, -1):
            match = re.match(r"^(\s*)env:\s*$", self.lines[index])
            if match:
                self.assertEqual(len(match.group(1)), 8, "timing variable is not step scoped")
                break
        else:
            self.fail("timing variable is not inside an env block")

        test_index = self.step_index_by_name(TEST_STEP_NAME)
        self.assertLess(test_index, timing_index)
        self.assertIn(self.lines[timing_index], self.block(test_index))

    def test_rust_test_command_and_concurrency_are_unchanged(self) -> None:
        test_block = self.block(self.step_index_by_name(TEST_STEP_NAME))
        self.assertIn("        run: cargo nextest run --all-features", test_block)
        self.assertTrue(
            any(
                line.strip() == "group: ci-${{ github.workflow }}-${{ github.ref }}"
                for line in self.lines
            ),
            "top-level concurrency group must stay unchanged",
        )

    def test_report_step_runs_always_after_tests_and_binds_test_step(self) -> None:
        test_index = self.step_index_by_name(TEST_STEP_NAME)
        test_block = self.block(test_index)
        id_lines = [line for line in test_block if line.strip().startswith("id:")]
        self.assertEqual(len(id_lines), 1, "test step needs exactly one id")
        test_id = id_lines[0].split(":", 1)[1].strip()
        self.assertTrue(test_id)

        report_index = self.step_index_containing("db_timing_report.py")
        self.assertLess(test_index, report_index)
        self.assertLess(report_index, self.coverage_start())

        report_text = "\n".join(self.block(report_index))
        self.assertIn("always()", report_text)
        self.assertIn(test_id, report_text)
        self.assertIn("if:", report_text)
        self.assertIn("db-timing.jsonl", report_text)

    def test_raw_diagnostics_are_uploaded_always_when_tests_fail(self) -> None:
        report_index = self.step_index_containing("db_timing_report.py")
        coverage_start = self.coverage_start()

        upload_starts = []
        for index, line in enumerate(self.lines):
            if not line.strip().startswith(f"uses: {UPLOAD_REF}"):
                continue
            for back in range(index, -1, -1):
                if self.lines[back].startswith("      - "):
                    upload_starts.append(back)
                    break

        quality_uploads = [index for index in upload_starts if index < coverage_start]
        matching = [
            index
            for index in quality_uploads
            if "db-timing" in "\n".join(self.block(index))
        ]
        self.assertEqual(len(matching), 1, "one quality upload step must carry the raw timing file")

        upload_index = matching[0]
        self.assertLess(report_index, upload_index)
        upload_text = "\n".join(self.block(upload_index))
        self.assertIn("always()", upload_text)
        self.assertIn("db-timing.jsonl", upload_text)
        self.assertIn(f"{UPLOAD_REF} # v7.0.1", upload_text)

    def test_coverage_job_is_untouched(self) -> None:
        coverage_text = "\n".join(self.lines[self.coverage_start() :])
        self.assertIn("cargo llvm-cov nextest", coverage_text)
        self.assertIn("--fail-under-lines 75", coverage_text)
        self.assertIn("name: rust-coverage", coverage_text)
        self.assertIn("path: lcov.info", coverage_text)
        self.assertNotIn(TIMING_VAR, coverage_text)


if __name__ == "__main__":
    unittest.main()
