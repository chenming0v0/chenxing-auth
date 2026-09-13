"""issue #710: static contract assertions for .github/workflows/ci.yml.

Stdlib-only, indentation-aware step-block checks (no YAML dependency). Guards the
template lifecycle CI wiring so a later refactor cannot silently:

- move CHENXING_TEST_DB_TIMING_FILE off the prepare/test steps or into coverage,
- drop the template prepare/cleanup steps or run cleanup non-always,
- decouple the report step from the prepare/test steps or drop the JUnit input,
- stop uploading the raw timing/JUnit diagnostics when tests or cleanup fail,
- touch the coverage gate, its artifact, or add timing there,
- break the default-profile JUnit output or the template wrapper contract.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
NEXTEST = ROOT / ".config" / "nextest.toml"

UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
UPLOAD_REF = f"actions/upload-artifact@{UPLOAD_SHA}"
TIMING_VAR = "CHENXING_TEST_DB_TIMING_FILE"
TIMING_VALUE = "${{ runner.temp }}/db-timing.jsonl"
TEST_STEP = "Run Rust tests in parallel"
PREPARE_STEP = "Prepare template database"
CLEANUP_STEP = "Cleanup template database"
REPORT_STEP = "Report database timing baseline"
UPLOAD_STEP = "Upload database timing diagnostics"
JUNIT_PATH = "target/nextest/default/junit.xml"
TEMPLATE_DB_VAR = "CHENXING_TEST_TEMPLATE_DATABASE"
PREFIX_VAR = "CHENXING_TEST_DATABASE_PREFIX"


class WorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = CI.read_text(encoding="utf-8").splitlines()

    # ------------------------------------------------------------- helpers
    def block(self, start: int) -> list[str]:
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
        self.fail(f"no step contains {needle!r}")

    def job_start(self, name: str) -> int:
        for index, line in enumerate(self.lines):
            if line == f"  {name}:":
                return index
        self.fail(f"job {name!r} not found")

    def job_text(self, name: str) -> str:
        start = self.job_start(name)
        end = len(self.lines)
        for index in range(start + 1, len(self.lines)):
            if re.match(r"^  [a-zA-Z0-9_-]+:\s*$", self.lines[index]):
                end = index
                break
        return "\n".join(self.lines[start:end])

    def next_step_name(self, start: int) -> str:
        for index in range(start + 1, len(self.lines)):
            if self.lines[index].startswith("      - name: "):
                return self.lines[index].split("name:", 1)[1].strip()
            if self.lines[index].startswith("      - "):
                # Unnamed step (bare `- run:` / `- uses:`): report a placeholder.
                return "<unnamed>"
        self.fail("no following step")

    def env_map(self, job: str) -> dict[str, str]:
        values: dict[str, str] = {}
        start = self.job_start(job)
        for index in range(start + 1, len(self.lines)):
            line = self.lines[index]
            if line.startswith("      - ") or re.match(r"^  [a-zA-Z0-9_-]+:\s*$", line):
                break
            if line.startswith("    env:"):
                continue
            match = re.match(r"^      ([A-Z0-9_]+):\s*(.*)$", line)
            if match:
                values[match.group(1)] = match.group(2).strip()
        return values

    # ------------------------------------------------------- timing scope
    def test_timing_variable_is_step_scoped_to_prepare_and_test(self) -> None:
        occurrences = [i for i, line in enumerate(self.lines) if TIMING_VAR in line]
        self.assertEqual(
            len(occurrences), 2, "timing variable must appear exactly on prepare + test"
        )
        for index in occurrences:
            self.assertEqual(self.lines[index], f"          {TIMING_VAR}: {TIMING_VALUE}")
            indent = len(self.lines[index]) - len(self.lines[index].lstrip())
            self.assertEqual(indent, 10, "timing variable must be a step-level env value")
            for back in range(index - 1, -1, -1):
                match = re.match(r"^(\s*)env:\s*$", self.lines[back])
                if match:
                    self.assertEqual(len(match.group(1)), 8, "timing env is not step scoped")
                    break
            else:
                self.fail("timing variable is not inside an env block")

        prepare_block = self.block(self.step_index_by_name(PREPARE_STEP))
        test_block = self.block(self.step_index_by_name(TEST_STEP))
        self.assertIn(f"          {TIMING_VAR}: {TIMING_VALUE}", prepare_block)
        self.assertIn(f"          {TIMING_VAR}: {TIMING_VALUE}", test_block)
        self.assertNotIn(TIMING_VAR, self.job_text("coverage"))

    # -------------------------------------------------- prepare/test/cleanup
    def test_prepare_runs_before_tests_after_tool_setup(self) -> None:
        prepare = self.step_index_by_name(PREPARE_STEP)
        test = self.step_index_by_name(TEST_STEP)
        install = self.step_index_containing("Install cargo-nextest")
        self.assertLess(install, prepare)
        self.assertLess(prepare, test)
        prepare_block = self.block(prepare)
        self.assertIn("id: template_prepare", "\n".join(prepare_block))
        self.assertIn("bash test_sh/test_database.sh prepare", "\n".join(prepare_block))

    def test_test_command_and_concurrency_unchanged(self) -> None:
        test_block = self.block(self.step_index_by_name(TEST_STEP))
        self.assertIn("        run: cargo nextest run --all-features", test_block)
        self.assertIn("id: rust_tests", "\n".join(test_block))
        self.assertTrue(
            any(
                line.strip() == "group: ci-${{ github.workflow }}-${{ github.ref }}"
                for line in self.lines
            )
        )

    def test_cleanup_runs_immediately_after_tests_and_always(self) -> None:
        test = self.step_index_by_name(TEST_STEP)
        cleanup = self.step_index_by_name(CLEANUP_STEP)
        self.assertEqual(self.next_step_name(test), CLEANUP_STEP)
        self.assertLess(test, cleanup)
        cleanup_block = self.block(cleanup)
        self.assertIn("if: ${{ always() }}", "\n".join(cleanup_block))
        self.assertIn("bash test_sh/test_database.sh cleanup", "\n".join(cleanup_block))

    # ------------------------------------------------------------- report
    def test_report_runs_when_prepare_or_tests_reached(self) -> None:
        report = self.step_index_by_name(REPORT_STEP)
        self.assertLess(self.step_index_by_name(CLEANUP_STEP), report)
        report_text = "\n".join(self.block(report))
        # Still runs whenever prepare or tests were reached; a prepare-only
        # failure must render the JSONL (it holds the error template_prepare row).
        self.assertIn("always()", report_text)
        self.assertIn("steps.template_prepare.outcome", report_text)
        self.assertIn("steps.rust_tests.outcome", report_text)
        self.assertIn("||", report_text)
        self.assertNotIn("steps.rust_tests.outcome == 'success'", report_text)
        self.assertIn("db_timing_report.py", report_text)

    def test_junit_argument_is_conditional_on_tests_having_run(self) -> None:
        report_text = "\n".join(self.block(self.step_index_by_name(REPORT_STEP)))
        # The --junit flag is added only when the test step was not skipped.
        self.assertIn(
            "TESTS_RAN: ${{ steps.rust_tests.outcome != 'skipped' }}", report_text
        )
        self.assertRegex(
            report_text, r"\[ \"\$TESTS_RAN\" = \"true\" \]"
        )
        self.assertIn(f"args+=(--junit {JUNIT_PATH})", report_text)
        # The report always runs against the JSONL even without JUnit.
        self.assertIn('args=("$RUNNER_TEMP/db-timing.jsonl")', report_text)

    def test_missing_junit_still_fails_closed_when_tests_ran(self) -> None:
        report_text = "\n".join(self.block(self.step_index_by_name(REPORT_STEP)))
        # --junit is passed through the array verbatim, so the reporter still
        # fails closed on a missing/partial JUnit when tests ran.
        self.assertIn(
            'python3 test_sh/db_timing_report.py ${args[@]+"${args[@]}"}'
            ' | tee "$report"',
            report_text,
        )
        self.assertNotIn('test -f', report_text)

    def test_step_summary_never_appends_an_empty_block(self) -> None:
        report_text = "\n".join(self.block(self.step_index_by_name(REPORT_STEP)))
        # The append is guarded on the report file being non-empty.
        self.assertIn('if [ -s "$report" ]; then', report_text)
        self.assertIn(">> \"$GITHUB_STEP_SUMMARY\"", report_text)
        # Heading is phase-neutral.
        self.assertIn("## DB timing baseline (issue #710)", report_text)
        self.assertNotIn("STAGE", report_text)

    def test_raw_diagnostics_uploaded_always_with_junit(self) -> None:
        report = self.step_index_by_name(REPORT_STEP)
        upload = self.step_index_by_name(UPLOAD_STEP)
        coverage_start = self.job_start("coverage")
        self.assertLess(report, upload)
        self.assertLess(upload, coverage_start)
        upload_text = "\n".join(self.block(upload))
        self.assertIn(f"uses: {UPLOAD_REF}", upload_text)
        self.assertIn("if: ${{ always() }}", upload_text)
        self.assertIn(f"{UPLOAD_REF} # v7.0.1", upload_text)
        self.assertIn("db-timing.jsonl", upload_text)
        self.assertIn("db-timing-report.txt", upload_text)
        self.assertIn(JUNIT_PATH, upload_text)

    # ------------------------------------------------------------ coverage
    def test_coverage_prepare_cleanup_and_gate_untouched(self) -> None:
        coverage = self.job_text("coverage")
        self.assertIn("bash test_sh/test_database.sh prepare", coverage)
        self.assertIn("bash test_sh/test_database.sh cleanup", coverage)
        self.assertIn("cargo llvm-cov nextest", coverage)
        self.assertIn("--fail-under-lines 75", coverage)
        self.assertIn("name: rust-coverage", coverage)
        self.assertIn("path: lcov.info", coverage)
        self.assertNotIn(TIMING_VAR, coverage)
        # Cleanup in coverage is always, inside that job's text.
        self.assertRegex(coverage, r"Cleanup template database\n\s+if: \$\{\{ always\(\) \}\}")

    # -------------------------------------------------------------- names
    def test_namespace_env_is_explicit_and_distinct_per_job(self) -> None:
        quality = self.env_map("quality")
        coverage = self.env_map("coverage")
        for env in (quality, coverage):
            self.assertIn("MIGRATION_DATABASE_URL", env)
            self.assertIn(TEMPLATE_DB_VAR, env)
            self.assertIn(PREFIX_VAR, env)

        q_prefix = quality[PREFIX_VAR]
        q_template = quality[TEMPLATE_DB_VAR]
        c_prefix = coverage[PREFIX_VAR]
        c_template = coverage[TEMPLATE_DB_VAR]
        self.assertNotEqual(q_prefix, c_prefix)
        self.assertIn("_quality_", q_prefix)
        self.assertIn("_coverage_", c_prefix)
        # template database is exactly prefix + "template".
        self.assertEqual(q_template, q_prefix + "template")
        self.assertEqual(c_template, c_prefix + "template")

    def test_no_database_url_fallback_in_wrapper(self) -> None:
        script = (ROOT / "test_sh" / "test_database.sh").read_text(encoding="utf-8")
        self.assertIn("MIGRATION_DATABASE_URL", script)
        self.assertNotIn("DATABASE_URL:", script)
        self.assertNotIn(": \"${DATABASE_URL", script)

        # DATABASE_URL may be loaded as an optional protection variable, but it
        # must never appear in the required list or the missing-variable loop.
        required_line = next(
            line for line in script.splitlines() if line.startswith("required=(")
        )
        optional_line = next(
            line for line in script.splitlines() if line.startswith("optional=(")
        )
        self.assertNotIn("DATABASE_URL", required_line.split())
        self.assertEqual(optional_line, "optional=(DATABASE_URL)")
        missing_loop = script.split("missing=()", 1)[1].split("done", 1)[0]
        self.assertIn('for name in "${required[@]}"', missing_loop)

    # ---------------------------------------------------- pre-Rust contracts
    def test_contracts_run_before_rust(self) -> None:
        contract = self.step_index_by_name("Validate DB timing report and template wrapper")
        self.assertLess(contract, self.step_index_by_name(TEST_STEP))
        text = "\n".join(self.block(contract))
        self.assertIn("bash -n test_sh/test_database.sh", text)
        self.assertIn("bash test_sh/test_database_contract.sh", text)
        self.assertIn("python3 -m unittest discover -s test_sh -p 'test_db_timing*.py'", text)


class NextestJunitConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = NEXTEST.read_text(encoding="utf-8").splitlines()

    def test_default_profile_emits_junit(self) -> None:
        text = "\n".join(self.lines)
        self.assertIn("[profile.default.junit]", text)
        self.assertIn('path = "junit.xml"', text)

    def test_no_new_profile_or_scheduling_change(self) -> None:
        profile_headers = [
            line for line in self.lines if line.lstrip("[").startswith("profile.")
        ]
        self.assertEqual(
            profile_headers,
            ["[[profile.default.overrides]]", "[profile.default.junit]"],
        )
        # The existing serial override is preserved untouched.
        self.assertIn("quota-refund-serial = { max-threads = 1 }", self.lines)
        self.assertTrue(
            any("oauth::quota::quota_refund::tests::" in line for line in self.lines)
        )


if __name__ == "__main__":
    unittest.main()
