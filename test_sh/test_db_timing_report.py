"""issue #710: contract tests for test_sh/db_timing_report.py.

These tests pin the shared JSONL emitter contract and the report CLI behavior.
They are stdlib-only and invoke the CLI as a subprocess, so they never import
project code or touch Rust/Cargo.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "db_timing_report.py"
sys.path.insert(0, str(SCRIPT.parent))
import db_timing_report as report_module  # noqa: E402


def fixture_record(identity: str = "oauth::authorize::happy_path") -> dict:
    return {
        "version": 1,
        "event": "fixture",
        "binary_name": "oauth",
        "test_identity": identity,
        "pid": 4321,
        "database_mode": "schema",
        "outcome": "ok",
        "phases_ms": {
            "bootstrap_connection": 10.0,
            "drop_create_schema": 5.0,
            "pool_connect": 2.0,
            "migrate": 40.0,
            "sequence_reset": 0,
        },
    }


def migration_record() -> dict:
    return {
        "version": 1,
        "event": "migration",
        "binary_name": "oauth",
        "test_identity": "oauth::migrate",
        "pid": 9999,
        "database_mode": "schema",
        "outcome": "ok",
        "phases_ms": {
            "migration_lock_wait_ms": 250.0,
            "migration_apply_ms": 180.0,
        },
    }


def template_fixture_record(identity: str = "integration::repository::case") -> dict:
    return {
        "version": 2,
        "event": "fixture",
        "binary_name": "integration_storage",
        "test_identity": identity,
        "pid": 4321,
        "database_mode": "template",
        "outcome": "ok",
        "phases_ms": {
            "bootstrap_connection": 10.0,
            "database_clone_ms": 30.0,
            "pool_connect": 2.0,
            "sequence_reset": 0,
        },
        "fixture_total_ms": 55.0,
    }


def template_prepare_record() -> dict:
    return {
        "version": 2,
        "event": "template_prepare",
        "binary_name": "test_database",
        "test_identity": "prepare",
        "pid": 700,
        "database_mode": "template",
        "outcome": "ok",
        "phases_ms": {"template_prepare_ms": 1200.0},
    }


CANDIDATE_A = "integration::repository::postgres_repositories_round_trip_users_and_clients"
CANDIDATE_B = (
    "integration::repository::postgres_transaction_user_insert_and_missing_client_paths_work"
)


def candidate_fixture_record(identity: str) -> dict:
    return {
        "version": 1,
        "event": "fixture",
        "binary_name": "integration_storage",
        "test_identity": identity,
        "pid": 5500,
        "database_mode": "schema",
        "outcome": "ok",
        "phases_ms": {
            "bootstrap_connection": 10.0,
            "drop_create_schema": 5.0,
            "pool_connect": 2.0,
            "migrate": 40.0,
            "sequence_reset": 0,
        },
    }


def junit_xml(*cases) -> str:
    body = "".join(
        f'<testcase name="{name}" classname="{classname}" time="{time}"/>'
        for name, classname, time in cases
    )
    return f'<?xml version="1.0"?><testsuites><testsuite name="storage">{body}</testsuite></testsuites>'


class ReportCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "timing.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_report(self, content) -> subprocess.CompletedProcess[str]:
        if isinstance(content, bytes):
            self.path.write_bytes(content)
        else:
            self.path.write_text(content, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path)],
            text=True,
            capture_output=True,
            check=False,
        )

    def run_missing(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path)],
            text=True,
            capture_output=True,
            check=False,
        )

    def run_report_junit(self, content, junit_xml) -> subprocess.CompletedProcess[str]:
        if isinstance(content, bytes):
            self.path.write_bytes(content)
        else:
            self.path.write_text(content, encoding="utf-8")
        junit_path = Path(self._tmp.name) / "junit.xml"
        junit_path.write_text(junit_xml, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path), "--junit", str(junit_path)],
            text=True,
            capture_output=True,
            check=False,
        )

    def jsonl(self, *records: dict) -> str:
        return "\n".join(json.dumps(record) for record in records) + "\n"

    def assert_fails_closed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "", "failed reports must not print a report")

    def phase_row(self, result: subprocess.CompletedProcess[str], phase: str) -> list[str]:
        for line in result.stdout.splitlines():
            cells = line.split()
            if cells and cells[0] == phase:
                return cells
        self.fail(f"phase {phase!r} not found in report:\n{result.stdout}")


class EmitterContractTest(ReportCliTest):
    def test_fixture_sample_shape_is_accepted(self) -> None:
        result = self.run_report(self.jsonl(fixture_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Schema fixture (v1) — 1 record(s), ok=1, error=0", result.stdout)

    def test_migration_sample_shape_is_accepted(self) -> None:
        result = self.run_report(self.jsonl(migration_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Schema migration (v1) — 1 record(s), ok=1, error=0", result.stdout)
        lock_row = self.phase_row(result, "migration_lock_wait_ms")
        self.assertEqual(lock_row[1], "1")

    def test_ok_fixture_requires_exactly_five_phases(self) -> None:
        record = fixture_record()
        del record["phases_ms"]["sequence_reset"]
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_ok_migration_requires_lock_and_apply(self) -> None:
        record = migration_record()
        del record["phases_ms"]["migration_apply_ms"]
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_error_fixture_may_report_only_reached_phases(self) -> None:
        record = fixture_record()
        record["outcome"] = "error"
        record["phases_ms"] = {"bootstrap_connection": 7.5}
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Schema fixture (v1) — 1 record(s), ok=0, error=1", result.stdout)
        self.assertIn("bootstrap_connection", result.stdout)
        self.assertNotIn("pool_connect", result.stdout)

    def test_error_migration_may_omit_lock_when_connect_failed(self) -> None:
        record = migration_record()
        record["outcome"] = "error"
        record["phases_ms"] = {}
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(no reached phase)", result.stdout)

    def test_apply_without_lock_is_rejected(self) -> None:
        record = migration_record()
        record["phases_ms"] = {"migration_apply_ms": 12.0}
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_extra_field_is_rejected(self) -> None:
        record = fixture_record()
        record["secret"] = "do-not-log"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_missing_metadata_field_is_rejected(self) -> None:
        record = fixture_record()
        del record["pid"]
        self.assert_fails_closed(self.run_report(self.jsonl(record)))


class MalformedInputTest(ReportCliTest):
    def test_missing_file_fails_closed(self) -> None:
        self.assert_fails_closed(self.run_missing())

    def test_empty_file_fails_closed(self) -> None:
        self.assert_fails_closed(self.run_report(""))

    def test_whitespace_only_content_is_rejected(self) -> None:
        self.assert_fails_closed(self.run_report("   \n"))

    def test_interior_blank_line_is_rejected(self) -> None:
        content = self.jsonl(fixture_record()).rstrip("\n") + "\n\n" + json.dumps(migration_record()) + "\n"
        self.assert_fails_closed(self.run_report(content))

    def test_malformed_json_is_rejected(self) -> None:
        self.assert_fails_closed(self.run_report("{\n"))

    def test_partial_trailing_line_is_rejected(self) -> None:
        content = self.jsonl(fixture_record()) + '{"version": 1, "event": "fixture"'
        self.assert_fails_closed(self.run_report(content))

    def test_invalid_utf8_is_rejected(self) -> None:
        self.assert_fails_closed(self.run_report(b"\xff\xfe\x00bad\n"))

    def test_bool_pid_is_rejected(self) -> None:
        record = fixture_record()
        record["pid"] = True
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_bool_phase_value_is_rejected(self) -> None:
        record = fixture_record()
        record["phases_ms"]["pool_connect"] = True
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_nan_is_rejected(self) -> None:
        raw = json.dumps(fixture_record()).replace("10.0", "NaN", 1)
        self.assert_fails_closed(self.run_report(raw + "\n"))

    def test_infinity_token_is_rejected(self) -> None:
        raw = json.dumps(fixture_record()).replace("10.0", "Infinity", 1)
        self.assert_fails_closed(self.run_report(raw + "\n"))

    def test_overflow_to_infinity_is_rejected(self) -> None:
        raw = json.dumps(fixture_record()).replace("10.0", "1e400", 1)
        self.assert_fails_closed(self.run_report(raw + "\n"))

    def test_negative_duration_is_rejected(self) -> None:
        record = fixture_record()
        record["phases_ms"]["migrate"] = -0.001
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_non_numeric_duration_is_rejected(self) -> None:
        record = fixture_record()
        record["phases_ms"]["migrate"] = "40"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_unknown_event_is_rejected(self) -> None:
        record = fixture_record()
        record["event"] = "benchmark"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_unknown_phase_is_rejected(self) -> None:
        record = fixture_record()
        record["phases_ms"]["mystery"] = 1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_migration_phase_in_fixture_is_rejected(self) -> None:
        record = fixture_record()
        del record["phases_ms"]["migrate"]
        record["phases_ms"]["migration_apply_ms"] = 1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_unsupported_version_is_rejected(self) -> None:
        record = fixture_record()
        record["version"] = 2
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_float_version_is_rejected(self) -> None:
        record = fixture_record()
        record["version"] = 1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_empty_identity_is_rejected(self) -> None:
        record = fixture_record(identity="   ")
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_zero_pid_is_rejected(self) -> None:
        record = fixture_record()
        record["pid"] = 0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_unknown_database_mode_is_rejected(self) -> None:
        record = fixture_record()
        record["database_mode"] = "database"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_unknown_outcome_is_rejected(self) -> None:
        record = fixture_record()
        record["outcome"] = "maybe"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_failure_does_not_leak_raw_identity(self) -> None:
        record = fixture_record(identity="SECRET-IDENTITY-TOKEN")
        del record["phases_ms"]["sequence_reset"]
        result = self.run_report(self.jsonl(record))
        self.assert_fails_closed(result)
        self.assertNotIn("SECRET-IDENTITY-TOKEN", result.stderr)
        self.assertNotIn("SECRET-IDENTITY-TOKEN", result.stdout)
        self.assertNotIn("phases_ms", result.stderr)

    def test_failure_prints_no_phase_table(self) -> None:
        record = fixture_record()
        del record["phases_ms"]["sequence_reset"]
        result = self.run_report(self.jsonl(record))
        self.assert_fails_closed(result)
        self.assertNotIn("bootstrap_connection", result.stdout)

    def test_duplicate_metadata_key_is_rejected(self) -> None:
        raw = json.dumps(fixture_record())
        raw = raw[:-1] + ', "SECRET_DUP_KEY": 1, "SECRET_DUP_KEY": 2}'
        result = self.run_report(raw + "\n")
        self.assert_fails_closed(result)
        self.assertNotIn("SECRET_DUP_KEY", result.stderr)

    def test_duplicate_phase_key_is_rejected(self) -> None:
        raw = json.dumps(fixture_record()).replace(
            '"migrate": 40.0', '"migrate": 40.0, "migrate": 41.0'
        )
        self.assert_fails_closed(self.run_report(raw + "\n"))

    def test_duplicate_key_inside_phases_object_is_rejected(self) -> None:
        raw = json.dumps(fixture_record()).replace(
            '"migrate": 40.0', '"migrate": 40.0, "SECRET_PHASE": 1, "SECRET_PHASE": 2'
        )
        result = self.run_report(raw + "\n")
        self.assert_fails_closed(result)
        self.assertNotIn("SECRET_PHASE", result.stderr)


class ReportStatisticsTest(ReportCliTest):
    def test_single_fixture_count_sum_median_p95_max(self) -> None:
        record = fixture_record()
        record["phases_ms"] = {
            "bootstrap_connection": 10.0,
            "drop_create_schema": 20.0,
            "pool_connect": 30.0,
            "migrate": 40.0,
            "sequence_reset": 0,
        }
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)

        bootstrap = self.phase_row(result, "bootstrap_connection")
        self.assertEqual(bootstrap[1:], ["1", "10", "10", "10", "10"])
        sequence = self.phase_row(result, "sequence_reset")
        self.assertEqual(sequence[1:], ["1", "0", "0", "0", "0"])

    def test_p95_is_nearest_rank_not_interpolated(self) -> None:
        # Five samples 1,2,3,4,100: nearest-rank p95 is 100; interpolation would be lower.
        samples = [1.0, 2.0, 3.0, 4.0, 100.0]
        rows = []
        for index, sample in enumerate(samples):
            rec = fixture_record(identity=f"call-{index}")
            rec["phases_ms"] = {
                "bootstrap_connection": sample,
                "drop_create_schema": 0,
                "pool_connect": 0,
                "migrate": 0,
                "sequence_reset": 0,
            }
            rows.append(rec)
        result = self.run_report(self.jsonl(*rows))
        self.assertEqual(result.returncode, 0, result.stderr)
        bootstrap = self.phase_row(result, "bootstrap_connection")
        self.assertEqual(bootstrap[1], "5")
        self.assertEqual(bootstrap[2], "110")
        self.assertEqual(bootstrap[3], "3")
        self.assertEqual(bootstrap[4], "100")
        self.assertEqual(bootstrap[5], "100")
        self.assertNotEqual(bootstrap[4], "80.8")

    def test_median_and_format_rounding(self) -> None:
        rows = []
        for sample in (1.0004, 2.0):
            record = fixture_record(identity=f"round-{sample}")
            record["phases_ms"] = {"bootstrap_connection": sample, "sequence_reset": 0}
            rows.append(record)
        # Fill the remaining required phases for successful fixtures.
        for record in rows:
            record["phases_ms"].update(
                {"drop_create_schema": 0, "pool_connect": 0, "migrate": 0}
            )
        result = self.run_report(self.jsonl(*rows))
        self.assertEqual(result.returncode, 0, result.stderr)
        bootstrap = self.phase_row(result, "bootstrap_connection")
        self.assertEqual(bootstrap[3], "1.5")

    def test_repeated_calls_are_not_deduplicated(self) -> None:
        record = fixture_record()
        result = self.run_report(self.jsonl(record, dict(record)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Schema fixture (v1) — 2 record(s), ok=2, error=0", result.stdout)
        self.assertEqual(self.phase_row(result, "bootstrap_connection")[1], "2")

    def test_fixture_and_migration_outcomes_are_counted_separately(self) -> None:
        fixture_ok = fixture_record()
        fixture_err = fixture_record(identity="oauth::authorize::boom")
        fixture_err["outcome"] = "error"
        fixture_err["phases_ms"] = {"bootstrap_connection": 3.0}
        migration_ok = migration_record()
        migration_err = migration_record()
        migration_err["outcome"] = "error"
        migration_err["phases_ms"] = {"migration_lock_wait_ms": 9.0}

        result = self.run_report(
            self.jsonl(fixture_ok, fixture_err, migration_ok, migration_err)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Records: 4 total (schema_fixture=2, schema_migration=2, "
            "template_fixture=0, template_prepare=0)",
            result.stdout,
        )
        self.assertIn("Schema fixture (v1) — 2 record(s), ok=1, error=1", result.stdout)
        self.assertIn("Schema migration (v1) — 2 record(s), ok=1, error=1", result.stdout)

    def test_labels_are_phase_neutral_and_mode_is_inferred(self) -> None:
        result = self.run_report(self.jsonl(fixture_record(), template_fixture_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DB timing report (issue #710)", result.stdout)
        self.assertNotIn("STAGE", result.stdout)
        self.assertIn("inferred from the emitted rows", result.stdout)
        # Per-group labels stay mode/version based, not phase based.
        self.assertIn("Schema fixture (v1)", result.stdout)
        self.assertIn("Template fixture (v2)", result.stdout)

    def test_report_states_nesting_and_wall_clock_caveats(self) -> None:
        result = self.run_report(self.jsonl(fixture_record(), migration_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("may be summed", result.stdout)
        self.assertIn("double count", result.stdout)
        self.assertIn("wall-clock speedup", result.stdout)
        self.assertIn("do not join fixture rows", result.stdout)
        self.assertIn("not the total number of tests", result.stdout)

    def test_median_midpoint_stays_finite_for_large_finite_samples(self) -> None:
        huge = 1.7e308
        value = report_module.median([huge, huge])
        self.assertTrue(math.isfinite(value))
        self.assertEqual(value, huge)

    def test_single_large_finite_sample_still_reports(self) -> None:
        record = fixture_record()
        record["phases_ms"] = {
            "bootstrap_connection": 1.7e308,
            "drop_create_schema": 0,
            "pool_connect": 0,
            "migrate": 0,
            "sequence_reset": 0,
        }
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.phase_row(result, "bootstrap_connection")
        self.assertEqual(row[4], row[5])

    def test_aggregate_overflow_fails_closed_without_partial_report(self) -> None:
        rows = []
        for index in range(2):
            record = fixture_record(identity=f"huge-{index}")
            record["phases_ms"] = {
                "bootstrap_connection": 1.7e308,
                "drop_create_schema": 0,
                "pool_connect": 0,
                "migrate": 0,
                "sequence_reset": 0,
            }
            rows.append(record)
        self.assert_fails_closed(self.run_report(self.jsonl(*rows)))

    def test_positive_report_does_not_echo_identities(self) -> None:
        record = fixture_record(identity="SECRET-IDENTITY-TOKEN")
        record["binary_name"] = "SECRET-BINARY"
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SECRET-IDENTITY-TOKEN", result.stdout)
        self.assertNotIn("SECRET-BINARY", result.stdout)


class V2TemplateContractTest(ReportCliTest):
    def test_template_fixture_shape_is_accepted(self) -> None:
        result = self.run_report(self.jsonl(template_fixture_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Template fixture (v2) — 1 record(s), ok=1, error=0", result.stdout)
        row = self.phase_row(result, "database_clone_ms")
        self.assertEqual(row[1], "1")
        total = self.phase_row(result, "fixture_total_ms")
        self.assertEqual(total[1], "1")

    def test_template_prepare_shape_is_accepted(self) -> None:
        result = self.run_report(self.jsonl(template_prepare_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Template prepare (v2) — 1 record(s), ok=1, error=0", result.stdout)
        row = self.phase_row(result, "template_prepare_ms")
        self.assertEqual(row[2], "1200")

    def test_mixed_versions_are_reported_per_group(self) -> None:
        result = self.run_report(
            self.jsonl(fixture_record(), template_fixture_record(), template_prepare_record())
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Records: 3 total (schema_fixture=1, schema_migration=0, "
            "template_fixture=1, template_prepare=1)",
            result.stdout,
        )

    def test_mixed_v1_v2_are_independent(self) -> None:
        # A v1 schema fixture must not borrow the v2 template phases and vice versa.
        v1 = fixture_record()
        v2 = template_fixture_record()
        result = self.run_report(self.jsonl(v1, v2))
        self.assertEqual(result.returncode, 0, result.stderr)
        schema_start = result.stdout.index("Schema fixture (v1)")
        schema_end = result.stdout.index("Schema migration (v1)")
        template_start = result.stdout.index("Template fixture (v2)")
        template_end = result.stdout.index("Template prepare (v2)")
        schema_block = result.stdout[schema_start:schema_end]
        template_block = result.stdout[template_start:template_end]
        self.assertIn("migrate", schema_block)
        self.assertNotIn("database_clone_ms", schema_block)
        self.assertNotIn("migrate ", template_block)
        self.assertIn("database_clone_ms", template_block)

    def test_template_fixture_requires_total(self) -> None:
        record = template_fixture_record()
        del record["fixture_total_ms"]
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_prepare_rejects_total_field(self) -> None:
        record = template_prepare_record()
        record["fixture_total_ms"] = 5.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_fixture_rejects_v1_phases(self) -> None:
        record = template_fixture_record()
        del record["phases_ms"]["database_clone_ms"]
        record["phases_ms"]["migrate"] = 1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_fixture_requires_all_four_phases_on_ok(self) -> None:
        record = template_fixture_record()
        del record["phases_ms"]["sequence_reset"]
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_fixture_error_keeps_only_reached(self) -> None:
        record = template_fixture_record()
        record["outcome"] = "error"
        record["phases_ms"] = {"bootstrap_connection": 4.0}
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Template fixture (v2) — 1 record(s), ok=0, error=1", result.stdout)

    def test_template_fixture_negative_total_is_rejected(self) -> None:
        record = template_fixture_record()
        record["fixture_total_ms"] = -1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_fixture_nan_total_is_rejected(self) -> None:
        raw = json.dumps(template_fixture_record()).replace('"fixture_total_ms": 55.0', '"fixture_total_ms": NaN')
        self.assert_fails_closed(self.run_report(raw + "\n"))

    def test_template_prepare_rejects_schema_phases(self) -> None:
        record = template_prepare_record()
        record["phases_ms"]["pool_connect"] = 1.0
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_v2_floats_and_wrong_mode_rejected(self) -> None:
        record = template_fixture_record()
        record["version"] = 1
        self.assert_fails_closed(self.run_report(self.jsonl(record)))
        record = template_prepare_record()
        record["database_mode"] = "schema"
        self.assert_fails_closed(self.run_report(self.jsonl(record)))

    def test_template_prepare_error_may_have_empty_phases(self) -> None:
        record = template_prepare_record()
        record["outcome"] = "error"
        record["phases_ms"] = {}
        result = self.run_report(self.jsonl(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Template prepare (v2) — 1 record(s), ok=0, error=1", result.stdout)
        self.assertIn("(no reached phase)", result.stdout)

    def test_template_costs_are_visible_and_separate(self) -> None:
        result = self.run_report(
            self.jsonl(template_fixture_record(), template_prepare_record())
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Template cost visibility", result.stdout)
        self.assertIn("database_clone_ms", result.stdout)
        self.assertIn("template_prepare_ms", result.stdout)
        self.assertIn("fixture_total_ms", result.stdout)


class JunitComparisonTest(ReportCliTest):
    def test_two_candidates_comparison_uses_v1_estimate(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
            migration_record(),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        result = self.run_report_junit(records, xml)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("JUnit comparison (two fixed candidates; basis per row)", result.stdout)
        self.assertNotIn("STAGE", result.stdout)
        self.assertIn("identifies whether that candidate still emits v1", result.stdout)
        row = self.phase_row(result, CANDIDATE_A)
        # fixture estimate = 10+5+2+40+0 = 57 ms; JUnit 0.120s = 120 ms.
        self.assertEqual(row[1], "120.000")
        self.assertEqual(row[2], "57.000")
        self.assertEqual(row[3], "63.000")
        self.assertIn("sum of schema stages", result.stdout)

    def test_v2_fixture_basis_is_total(self) -> None:
        v2 = template_fixture_record(CANDIDATE_A)
        records = self.jsonl(v2, candidate_fixture_record(CANDIDATE_B))
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.070"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        result = self.run_report_junit(records, xml)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.phase_row(result, CANDIDATE_A)
        self.assertEqual(row[1], "70.000")
        self.assertEqual(row[2], "55.000")
        self.assertIn("fixture_total_ms (v2)", result.stdout)

    def test_missing_candidate_testcase_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml((CANDIDATE_A, "chenxing-auth::storage", "0.120"))
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_missing_fixture_row_fails(self) -> None:
        records = self.jsonl(candidate_fixture_record(CANDIDATE_A))
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_duplicate_testcase_is_ambiguous_and_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_A, "chenxing-auth::storage", "0.130"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_duplicate_fixture_row_is_ambiguous_and_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_wrong_classname_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::admin", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_bare_storage_classname_is_rejected(self) -> None:
        # nextest 0.9.143 uses `chenxing-auth::storage`; a bare `storage` alias
        # must never be accepted.
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_wrong_fixture_binary_fails(self) -> None:
        wrong = candidate_fixture_record(CANDIDATE_A)
        wrong["binary_name"] = "some_other_binary"
        records = self.jsonl(wrong, candidate_fixture_record(CANDIDATE_B))
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_error_fixture_row_fails(self) -> None:
        errored = candidate_fixture_record(CANDIDATE_A)
        errored["outcome"] = "error"
        errored["phases_ms"] = {"bootstrap_connection": 5.0}
        records = self.jsonl(errored, candidate_fixture_record(CANDIDATE_B))
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.120"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_nonfinite_millisecond_conversion_fails_closed(self) -> None:
        # 1e308 seconds is finite but overflows to infinity once multiplied by 1000.
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "1e308"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_infinite_junit_time_attribute_fails_closed(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "Infinity"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_failed_testcase_disqualifies(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = (
            '<?xml version="1.0"?><testsuites><testsuite name="chenxing-auth::storage">'
            f'<testcase name="{CANDIDATE_A}" classname="chenxing-auth::storage" time="0.120">'
            '<failure message="boom">stack</failure></testcase>'
            f'<testcase name="{CANDIDATE_B}" classname="chenxing-auth::storage" time="0.200"/>'
            "</testsuite></testsuites>"
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_flaky_and_rerun_children_disqualify(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        for tag in ("flakyFailure", "flakyError", "rerunFailure", "rerunError"):
            xml = (
                '<?xml version="1.0"?><testsuites><testsuite name="chenxing-auth::storage">'
                f'<testcase name="{CANDIDATE_A}" classname="chenxing-auth::storage" time="0.120">'
                f'<{tag}/></testcase>'
                f'<testcase name="{CANDIDATE_B}" classname="chenxing-auth::storage" time="0.200"/>'
                "</testsuite></testsuites>"
            )
            with self.subTest(tag=tag):
                self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_absent_junit_file_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        self.path.write_text(records, encoding="utf-8")
        missing = Path(self._tmp.name) / "nope.xml"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.path), "--junit", str(missing)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assert_fails_closed(result)

    def test_invalid_junit_xml_fails(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        self.assert_fails_closed(self.run_report_junit(records, "<testsuites>"))

    def test_large_negative_residual_fails_beyond_tolerance(self) -> None:
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        # fixture estimate is 57 ms; 0.010s = 10 ms -> residual -47 ms.
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.010"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        self.assert_fails_closed(self.run_report_junit(records, xml))

    def test_small_negative_residual_within_rounding_is_clamped(self) -> None:
        # fixture estimate 57 ms; 0.0567s = 56.7 ms -> residual -0.3 ms.
        records = self.jsonl(
            candidate_fixture_record(CANDIDATE_A),
            candidate_fixture_record(CANDIDATE_B),
        )
        xml = junit_xml(
            (CANDIDATE_A, "chenxing-auth::storage", "0.0567"),
            (CANDIDATE_B, "chenxing-auth::storage", "0.200"),
        )
        result = self.run_report_junit(records, xml)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.phase_row(result, CANDIDATE_A)[3], "0.000")

    def test_junit_without_candidates_does_not_affect_plain_report(self) -> None:
        # Plain report (no --junit) must stay independent of candidate rows.
        result = self.run_report(self.jsonl(fixture_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("JUnit comparison", result.stdout)


if __name__ == "__main__":
    unittest.main()
