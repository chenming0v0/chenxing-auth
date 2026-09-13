#!/usr/bin/env python3
"""JUnit correlation for the issue #710 database timing report.

Stage 1 only compares the two schema-path candidates that the template refactor
will eventually migrate first. Each candidate must resolve to exactly one JUnit
``testcase`` and exactly one ``fixture`` timing row; anything missing or
ambiguous is an error, never a guess. There is no general PID/identity join.

``body_residual_ms`` is ``test_elapsed_ms - fixture_ms`` and is labeled as a
body **and runtime overhead** estimate: the JUnit elapsed time also contains the
diagnostic write, harness scheduling, and any other per-test overhead, so it is
not pure body time. nextest writes ``time`` in seconds rounded to 3 decimals, so
the comparison tolerates at most 0.5 ms of rounding disagreement; a larger
negative residual fails the comparison rather than being hidden.

Confirmed nextest 0.9.143 shape: the storage integration testsuite is named
``chenxing-auth::storage`` and each ``testcase`` uses that same value as
``classname`` with the module path as ``name``. A ``testcase`` carrying any
``failure`` / ``error`` / ``skipped`` child, or a ``flakyFailure`` /
``flakyError`` / ``rerunFailure`` / ``rerunError`` child, disqualifies the
evidence. A partial file (missing candidate, e.g. after failfast) or an absent
file fails the comparison; the raw artifacts are still preserved by CI.

Standard library only.
"""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from pathlib import Path

# Exact nextest 0.9.143 storage integration classname. There is no bare-`storage`
# alias: the classname is always the `chenxing-auth::storage` binary prefix.
STORAGE_JUNIT_CLASSNAME = "chenxing-auth::storage"

# Fixture rows must carry this fixed binary label and an ok outcome; a wrong
# binary or a caught setup error is not trial evidence.
EXPECTED_FIXTURE_BINARY = "integration_storage"

# The exact two schema-path candidates. The identity is globally unique, so it is
# the sole correlation key on both the JUnit and timing sides.
CANDIDATES = (
    "integration::repository::postgres_repositories_round_trip_users_and_clients",
    "integration::repository::postgres_transaction_user_insert_and_missing_client_paths_work",
)

# nextest writes testcase `time` in seconds rounded to 3 decimals, so the two
# clocks may disagree by at most half a millisecond before a negative residual is
# treated as invalid evidence rather than rounding.
ROUNDING_TOLERANCE_MS = 0.5

# Any of these child elements makes the testcase ineligible as trial evidence.
DISQUALIFYING_CHILDREN = frozenset(
    {
        "failure",
        "error",
        "skipped",
        "flakyFailure",
        "flakyError",
        "rerunFailure",
        "rerunError",
    }
)

V1_BASIS = "sum of schema stages (v1 estimate; missing interstage overhead)"
V2_BASIS = "fixture_total_ms (v2)"


class JunitError(Exception):
    """JUnit input cannot satisfy the comparison. Messages carry no raw XML."""


def _storage_classnames() -> frozenset:
    """The only JUnit classname that authorizes storage candidate evidence."""
    return frozenset({STORAGE_JUNIT_CLASSNAME})


def load_testcases(path: Path) -> list[dict]:
    """Parse a JUnit XML file into testcase records; any problem raises."""
    try:
        data = path.read_bytes()
    except OSError:
        raise JunitError("cannot read JUnit file") from None

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise JunitError("invalid JUnit XML") from None

    testcases = []
    for element in root.iter("testcase"):
        time_attr = element.get("time")
        if time_attr is None:
            raise JunitError("JUnit testcase is missing its time attribute")
        try:
            seconds = float(time_attr)
        except ValueError:
            raise JunitError("JUnit time attribute is not numeric") from None
        if not math.isfinite(seconds) or seconds < 0:
            raise JunitError("JUnit time attribute is not finite nonnegative")
        # A finite seconds value can still overflow to infinity in milliseconds
        # (e.g. 1e308 * 1000); every reported value must stay finite.
        time_ms = seconds * 1000.0
        if not math.isfinite(time_ms):
            raise JunitError("JUnit time attribute overflows milliseconds")

        disqualified = any(
            child.tag in DISQUALIFYING_CHILDREN for child in element
        )
        testcases.append(
            {
                "name": element.get("name") or "",
                "classname": element.get("classname") or "",
                "disqualified": disqualified,
                "time_ms": time_ms,
            }
        )
    return testcases


def _fixture_timing(record: dict) -> tuple[str, float]:
    """Return (basis, ms) for one correlated fixture record."""
    if record["version"] == 2:
        total = record["fixture_total_ms"]
        if total is None:
            raise JunitError("v2 template fixture is missing fixture_total_ms")
        return V2_BASIS, total

    samples = list(record["phases"].values())
    try:
        total = math.fsum(samples)
    except OverflowError:
        raise JunitError("fixture timing aggregate is not finite") from None
    if not math.isfinite(total):
        raise JunitError("fixture timing aggregate is not finite")
    return V1_BASIS, total


def compare(records: list[dict], junit_path: Path) -> list[str]:
    """Render the JUnit comparison section, or raise if correlation fails."""
    testcases = load_testcases(junit_path)

    lines = [
        "",
        "JUnit comparison (stage 1 schema path; exactly two candidates)",
        "fixture_ms basis: v1 = sum of schema stages (estimate); v2 = fixture_total_ms",
        "",
    ]
    width = max(len(identity) for identity in CANDIDATES) + 2
    header = (
        f"{'identity':<{width}}{'test_elapsed_ms':>16}{'fixture_ms':>13}"
        f"{'body_residual_ms':>18}"
    )
    lines.append(header)
    lines.append("-" * len(header))

    classnames = _storage_classnames()
    for identity in CANDIDATES:
        matched = [
            tc
            for tc in testcases
            if tc["name"] == identity and tc["classname"] in classnames
        ]
        if len(matched) != 1:
            raise JunitError(
                f"expected exactly one JUnit testcase for {identity}, found {len(matched)}"
            )
        if matched[0]["disqualified"]:
            raise JunitError(
                f"JUnit testcase for {identity} is not a passing trial (failure/error/skipped/flaky/rerun)"
            )

        fixtures = [
            record
            for record in records
            if record["event"] == "fixture" and record["test_identity"] == identity
        ]
        if len(fixtures) != 1:
            raise JunitError(
                f"expected exactly one fixture row for {identity}, found {len(fixtures)}"
            )
        fixture = fixtures[0]
        if fixture["binary_name"] != EXPECTED_FIXTURE_BINARY:
            raise JunitError(
                f"fixture row for {identity} has an unexpected binary label"
            )
        if fixture["outcome"] != "ok":
            raise JunitError(f"fixture row for {identity} is not a successful fixture")

        basis, fixture_ms = _fixture_timing(fixture)
        elapsed_ms = matched[0]["time_ms"]
        residual_ms = elapsed_ms - fixture_ms
        if not math.isfinite(fixture_ms) or not math.isfinite(residual_ms):
            raise JunitError("comparison produced a non-finite value")
        if residual_ms < -ROUNDING_TOLERANCE_MS:
            raise JunitError(
                f"negative body residual beyond rounding tolerance for {identity}"
            )
        if residual_ms < 0:
            residual_ms = 0.0

        lines.append(
            f"{identity:<{width}}{elapsed_ms:>16.3f}{fixture_ms:>13.3f}{residual_ms:>18.3f}"
        )
        lines.append(f"    basis: {basis}")

    lines.append("")
    lines.append(
        "body_residual_ms = test_elapsed_ms - fixture_ms; it includes the test body, "
        "runtime overhead, and the diagnostic write, so it is not pure body time."
    )
    lines.append(
        "A negative residual within 0.5 ms is clamped for JUnit 3-decimal rounding; "
        "a larger negative residual fails the comparison. These two-test timings do "
        "not predict whole-suite speedup."
    )
    lines.append("")
    return lines
