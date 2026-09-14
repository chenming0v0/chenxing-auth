"""issue #710 转向后的 CI 静态契约断言。

只用标准库，缩进感知地解析 `.github/workflows/ci.yml`，不依赖 YAML 库。这些断言
锁定分片架构的关键不变量，防止后续重构悄悄破坏：

- 测试只在分片 job 里跑**一次**，不在 quality / coverage 里重复整套；
- 每个分片自带独立 PostgreSQL service（这是迁移锁不再跨分片排队的前提）；
- 分片用 `--partition slice:`，且**不在分片上判覆盖率门槛**；
- 覆盖率门槛只在合并 job 里判，且要求全部分片到齐；
- 合并 job 不重跑 Rust 测试、不重复模板 prepare/cleanup；
- 分片命名空间互不冲突，缺变量仍然硬失败。
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
MERGE_LCOV_STEP = "Merge shard coverage and enforce the line threshold"
MERGE_DIAGNOSTICS_STEP = "Merge shard diagnostics"
TEMPLATE_DB_VAR = "CHENXING_TEST_TEMPLATE_DATABASE"
PREFIX_VAR = "CHENXING_TEST_DATABASE_PREFIX"
SHARDS = 4


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

    # --------------------------------------------- sharding is the mechanism
    def test_test_job_shards_with_its_own_postgres_and_redis(self) -> None:
        test_job = self.job_text("test")
        self.assertIn("shard: [1, 2, 3, 4]", test_job)
        self.assertIn("fail-fast: false", test_job)
        # Each shard needs its own service containers: the migration advisory lock
        # id is derived from `current_database()`, so only a separate database per
        # shard actually removes the cross-shard serialization.
        self.assertIn("postgres:16-alpine", test_job)
        self.assertIn("redis:7-alpine", test_job)
        self.assertIn("pg_isready", test_job)

    def test_shard_count_matches_matrix(self) -> None:
        with_missing = self.step_index_containing("--expect-shards")
        self.assertTrue(with_missing >= 0)
        coverage = self.job_text("coverage")
        self.assertIn("--expect-shards ${{ env.SHARDS }}", coverage)
        matrix = re.search(r"shard: \[([^\]]+)\]", self.job_text("test"))
        assert matrix is not None, "test job must declare a shard matrix"
        declared = [part.strip() for part in matrix.group(1).split(",")]
        self.assertEqual(len(declared), SHARDS)
        self.assertIn("SHARDS", "\n".join(self.lines))

    def test_shards_use_slice_partition_and_no_threshold(self) -> None:
        test_block = "\n".join(self.block(self.step_index_by_name(TEST_STEP)))
        self.assertIn("cargo llvm-cov nextest", test_block)
        self.assertIn("--partition slice:${{ matrix.shard }}/${{ env.SHARDS }}", test_block)
        # `count:` is documented by nextest as strictly worse than `slice:`, and a
        # per-shard threshold would judge partial coverage.
        self.assertNotIn("--partition count:", test_block)
        self.assertNotIn("--fail-under-lines", test_block)

    def test_tests_run_exactly_once_across_the_workflow(self) -> None:
        # Only the sharded job may execute the suite; quality and coverage must not
        # run a second full pass.
        self.assertNotIn("nextest run", self.job_text("quality"))
        coverage = self.job_text("coverage")
        self.assertNotIn("llvm-cov nextest", coverage)
        self.assertNotIn("cargo nextest", coverage)
        self.assertIn("cargo llvm-cov nextest", self.job_text("test"))
        # The full suite runs once per shard, so there are exactly SHARDS runs.
        self.assertNotIn("Run Rust tests in parallel", coverage)

    # ------------------------------------------------- coverage: merge + gate
    def test_coverage_threshold_only_after_merge(self) -> None:
        coverage = self.job_text("coverage")
        merge_block = "\n".join(self.block(self.step_index_by_name(MERGE_LCOV_STEP)))
        self.assertIn("test_sh/merge_lcov.py", merge_block)
        self.assertIn("--fail-under-lines 75", merge_block)
        self.assertIn("--expect-shards ${{ env.SHARDS }}", merge_block)
        self.assertIn("--output lcov.info", merge_block)
        self.assertIn("name: rust-coverage", coverage)
        self.assertIn("path: lcov.info", coverage)

    def test_coverage_job_has_no_template_lifecycle_or_rebuild(self) -> None:
        coverage = self.job_text("coverage")
        # The template only serves the opt-in tests, which now live in the sharded
        # job; a coverage-side prepare/cleanup is pure added cost on the critical
        # path, and rebuilding Rust here would duplicate the shard builds.
        self.assertNotIn("test_database.sh prepare", coverage)
        self.assertNotIn("test_database.sh cleanup", coverage)
        self.assertNotIn("rust-toolchain", coverage)
        self.assertNotIn("rust-cache", coverage)

    def test_merged_diagnostics_feed_the_report(self) -> None:
        coverage = self.job_text("coverage")
        self.assertIn("test_sh/merge_diagnostics.py", coverage)
        self.assertIn("test_sh/db_timing_report.py", coverage)
        report_block = "\n".join(self.block(self.step_index_by_name(REPORT_STEP)))
        # A merged JUnit always exists once the merge step succeeded, so the
        # candidate comparison stays mandatory rather than silently skipped.
        self.assertIn("--junit merged-diagnostics/junit.xml", report_block)
        self.assertIn("db_timing_report.py merged-diagnostics/db-timing.jsonl", report_block)
        self.assertIn('if [ -s "$report" ]; then', report_block)
        self.assertIn('if [ ! -f merged-diagnostics/junit.xml ]', report_block)
        self.assertIn('>> "$GITHUB_STEP_SUMMARY"', report_block)
        self.assertIn("## DB timing baseline (issue #710)", report_block)

    def test_coverage_depends_on_all_shards(self) -> None:
        coverage = self.job_text("coverage")
        self.assertRegex(coverage, r"needs: \[test\]")
        # Shard artifacts are downloaded by pattern and flattened for the merger.
        self.assertIn("pattern: lcov-shard-*", coverage)
        self.assertIn("merge-multiple: true", coverage)
        self.assertIn("pattern: test-diagnostics-shard-*", coverage)

    # ------------------------------------------------ per-shard test lifecycle
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

    def test_prepare_runs_before_tests_after_tool_setup(self) -> None:
        prepare = self.step_index_by_name(PREPARE_STEP)
        test = self.step_index_by_name(TEST_STEP)
        install = self.step_index_containing("Install cargo-nextest and cargo-llvm-cov")
        self.assertLess(install, prepare)
        self.assertLess(prepare, test)
        prepare_block = self.block(prepare)
        self.assertIn("bash test_sh/test_database.sh prepare", "\n".join(prepare_block))

    def test_cleanup_runs_immediately_after_tests_and_always(self) -> None:
        test = self.step_index_by_name(TEST_STEP)
        cleanup = self.step_index_by_name(CLEANUP_STEP)
        self.assertEqual(self.next_step_name(test), CLEANUP_STEP)
        self.assertLess(test, cleanup)
        cleanup_block = self.block(cleanup)
        self.assertIn("if: ${{ always() }}", "\n".join(cleanup_block))
        self.assertIn("bash test_sh/test_database.sh cleanup", "\n".join(cleanup_block))

    def test_shard_artifacts_are_always_uploaded(self) -> None:
        coverage_upload = self.step_index_by_name("Upload shard coverage report")
        diagnostics_upload = self.step_index_by_name("Upload shard diagnostics")
        for index in (coverage_upload, diagnostics_upload):
            block = "\n".join(self.block(index))
            self.assertIn(f"uses: {UPLOAD_REF}", block)
            self.assertIn(f"{UPLOAD_REF} # v7.0.1", block)
        self.assertIn("if: ${{ always() }}", "\n".join(self.block(coverage_upload)))
        self.assertIn("if: ${{ always() }}", "\n".join(self.block(diagnostics_upload)))
        self.assertIn("lcov-shard-${{ matrix.shard }}.info", "\n".join(self.block(coverage_upload)))
        merged_upload = "\n".join(self.block(self.step_index_by_name("Upload merged diagnostics")))
        self.assertIn("merged-diagnostics/db-timing.jsonl", merged_upload)
        self.assertIn("merged-diagnostics/junit.xml", merged_upload)

    def test_merged_diagnostics_upload_is_always(self) -> None:
        block = "\n".join(self.block(self.step_index_by_name("Upload merged diagnostics")))
        self.assertIn("if: ${{ always() }}", block)
        self.assertIn("name: db-timing-diagnostics", block)

    def test_concurrency_guard_preserved(self) -> None:
        self.assertTrue(
            any(
                line.strip() == "group: ci-${{ github.workflow }}-${{ github.ref }}"
                for line in self.lines
            )
        )

    # -------------------------------------------------------------- names
    def test_namespace_env_is_explicit_and_shard_scoped(self) -> None:
        test_env = self.env_map("test")
        for env in ("MIGRATION_DATABASE_URL", TEMPLATE_DB_VAR, PREFIX_VAR):
            self.assertIn(env, test_env)
        prefix = test_env[PREFIX_VAR]
        template = test_env[TEMPLATE_DB_VAR]
        # The namespace grammar requires template == prefix + "template", and the
        # shard id must be in the prefix so parallel shards cannot collide.
        self.assertIn("_s${{ matrix.shard }}_", prefix)
        self.assertEqual(template, prefix + "template")

    def test_no_database_url_fallback_in_wrapper(self) -> None:
        script = (ROOT / "test_sh" / "test_database.sh").read_text(encoding="utf-8")
        self.assertIn("MIGRATION_DATABASE_URL", script)
        self.assertNotIn("DATABASE_URL:", script)
        self.assertNotIn(": \"${DATABASE_URL", script)

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
        self.assertLess(contract, self.job_start("test"))
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

    def test_no_extra_profile_or_scheduling_change(self) -> None:
        profile_headers = [
            line for line in self.lines if line.lstrip("[").startswith("profile.")
        ]
        self.assertEqual(
            profile_headers,
            ["[[profile.default.overrides]]", "[profile.default.junit]"],
        )
        self.assertIn("quota-refund-serial = { max-threads = 1 }", self.lines)
        self.assertTrue(
            any("oauth::quota::quota_refund::tests::" in line for line in self.lines)
        )


if __name__ == "__main__":
    unittest.main()
