"""issue #710 STAGE 0: contract tests for test_sh/db_timing_report.py.

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
        self.assertIn("Fixture calls: 1 (ok=1, error=0)", result.stdout)

    def test_migration_sample_shape_is_accepted(self) -> None:
        result = self.run_report(self.jsonl(migration_record()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Migration calls: 1 (ok=1, error=0)", result.stdout)
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
        self.assertIn("Fixture calls: 1 (ok=0, error=1)", result.stdout)
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
        self.assertIn("Fixture calls: 2 (ok=2, error=0)", result.stdout)
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
        self.assertIn("Records: 4 total (fixture=2, migration=2)", result.stdout)
        self.assertIn("Fixture calls: 2 (ok=1, error=1)", result.stdout)
        self.assertIn("Migration calls: 2 (ok=1, error=1)", result.stdout)

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


if __name__ == "__main__":
    unittest.main()
