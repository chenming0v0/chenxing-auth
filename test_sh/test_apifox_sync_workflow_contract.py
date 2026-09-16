"""Apifox 同步必须是独立工作流，不能再挂回 CI。"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "apifox-sync.yml"


class ApifoxSyncWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.lines = cls.text.splitlines()

    def test_workflow_exists_and_is_named(self) -> None:
        self.assertTrue(WORKFLOW.is_file())
        self.assertIn("name: Apifox Sync", self.lines)

    def test_push_to_dev_not_workflow_run(self) -> None:
        # workflow_run / CI-dispatched workflow_dispatch only see files on the
        # default branch (`releases`). push is the event that reads YAML from
        # the pushed commit, so this file can live on `dev`.
        self.assertIn("  push:", self.lines)
        self.assertIn("    branches: [dev]", self.lines)
        self.assertNotIn("  workflow_run:", self.lines)
        self.assertNotIn("    types: [completed]", self.lines)
        self.assertIn("  workflow_dispatch:", self.lines)

    def test_only_runs_when_the_spec_or_workflow_changes(self) -> None:
        self.assertIn("- openapi.yaml", self.text)
        self.assertIn("- .github/workflows/apifox-sync.yml", self.text)

    def test_job_is_restricted_to_dev(self) -> None:
        self.assertIn("if: github.ref == 'refs/heads/dev'", self.text)

    def test_uses_apifox_environment_secret_and_project(self) -> None:
        self.assertIn("environment: apifox", self.text)
        self.assertIn("API_FOX_KEY: ${{ secrets.API_FOX_KEY }}", self.text)
        self.assertIn("test -n \"$API_FOX_KEY\"", self.text)
        self.assertIn(
            "https://api.apifox.com/v1/projects/8642631/import-openapi?locale=zh-CN",
            self.text,
        )
        self.assertIn(
            "https://raw.githubusercontent.com/chenming0v0/chenxing-auth/dev/openapi.yaml",
            self.text,
        )

    def test_retries_without_continue_on_error(self) -> None:
        # Failures belong on this workflow. continue-on-error was only needed
        # when the job lived inside CI and blocked merges.
        self.assertIn("--retry 3", self.text)
        self.assertIn("--retry-delay 20", self.text)
        self.assertIn("--retry-all-errors", self.text)
        self.assertFalse(
            any(re.match(r"^\s+continue-on-error:", line) for line in self.lines)
        )

    def test_cancels_overlapping_imports(self) -> None:
        self.assertIn("  group: apifox-sync", self.lines)
        self.assertIn("  cancel-in-progress: true", self.lines)

    def test_does_not_checkout_or_use_unpinned_actions(self) -> None:
        # Import is by URL; a checkout would only add supply-chain surface.
        self.assertFalse(any(re.match(r"^\s+uses:", line) for line in self.lines))


if __name__ == "__main__":
    unittest.main()
