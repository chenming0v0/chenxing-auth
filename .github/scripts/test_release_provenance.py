#!/usr/bin/env python3
"""发布来源的离线回归：精确提交、分支、运行顺序及等待边界。"""

from __future__ import annotations

import copy
import io
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import call, patch
from urllib.parse import parse_qs, urlsplit

import verify_release_provenance as provenance


REPOSITORY = "chenming0v0/chenxing-auth"
SHA = "a" * 40
OTHER_SHA = "b" * 40
WORKFLOW_ID = 7


def ci_run(run_id: int = 1, **changes: object) -> dict:
    run = {
        "id": run_id,
        "run_number": run_id,
        "run_attempt": 1,
        "workflow_id": WORKFLOW_ID,
        "event": "push",
        "head_branch": "releases",
        "head_sha": SHA,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "status": "completed",
        "conclusion": "success",
    }
    return run | changes


class FakeApi(provenance.GitHubApi):
    def __init__(self, *snapshots: list[dict]):
        self.snapshots = snapshots or ([],)
        self.run_calls = 0
        self.workflow_calls = 0

    def workflow(self, repository: str) -> dict:
        self.workflow_calls += 1
        return {"id": WORKFLOW_ID, "name": "CI", "path": provenance.CI_PATH}

    def runs(self, repository: str, sha: str) -> list[dict]:
        index = min(self.run_calls, len(self.snapshots) - 1)
        self.run_calls += 1
        return copy.deepcopy(self.snapshots[index])


class Clock:
    def __init__(self):
        self.value = 0.0

    def now(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class CiResultTests(unittest.TestCase):
    def wait(self, api: FakeApi, timeout: int = 3) -> dict:
        clock = Clock()
        with redirect_stdout(io.StringIO()):
            return provenance.wait_for_ci(
                api,
                REPOSITORY,
                SHA,
                WORKFLOW_ID,
                timeout=timeout,
                interval=1,
                clock=clock.now,
                sleep=clock.sleep,
            )

    def test_success_requires_exact_releases_push_and_repository(self):
        unrelated = [
            ci_run(head_sha=OTHER_SHA),
            ci_run(head_branch="dev"),
            ci_run(event="pull_request"),
            ci_run(workflow_id=99),
            ci_run(repository={"full_name": "other/project"}),
            ci_run(head_repository={"full_name": "fork/chenxing-auth"}),
        ]
        for run in unrelated:
            with self.subTest(run=run), self.assertRaisesRegex(
                provenance.ProvenanceError, "超时"
            ):
                self.wait(FakeApi([run]), timeout=1)
        self.assertEqual(self.wait(FakeApi([ci_run()]))["head_sha"], SHA)

    def test_failure_cancel_and_other_terminal_results_reject(self):
        for result in ("failure", "cancelled", "timed_out", "neutral", "skipped"):
            api = FakeApi([ci_run(conclusion=result)])
            with self.subTest(result=result), self.assertRaisesRegex(
                provenance.ProvenanceError, result
            ):
                self.wait(api)
            self.assertEqual(api.run_calls, 1)

    def test_missing_then_pending_then_success_waits_without_real_sleep(self):
        api = FakeApi(
            [],
            [ci_run(status="queued", conclusion=None)],
            [ci_run(status="in_progress", conclusion=None)],
            [ci_run()],
        )
        self.assertEqual(self.wait(api)["conclusion"], "success")
        self.assertEqual(api.run_calls, 4)

    def test_pending_timeout_is_bounded(self):
        api = FakeApi([ci_run(status="waiting", conclusion=None)])
        with self.assertRaisesRegex(provenance.ProvenanceError, "超时"):
            self.wait(api, timeout=2)
        self.assertEqual(api.run_calls, 3)

    def test_newer_failure_cannot_be_hidden_by_older_success(self):
        api = FakeApi([ci_run(2, conclusion="failure"), ci_run(1)])
        with self.assertRaisesRegex(provenance.ProvenanceError, "#2.*failure"):
            self.wait(api)

    def test_newer_success_supersedes_old_failure(self):
        self.assertEqual(
            self.wait(FakeApi([ci_run(2), ci_run(1, conclusion="failure")]))["id"],
            2,
        )

    def test_latest_rerun_must_complete_before_release(self):
        api = FakeApi(
            [ci_run(2, run_attempt=2, status="in_progress", conclusion=None), ci_run(1)],
            [ci_run(2, run_attempt=2), ci_run(1)],
        )
        self.assertEqual(self.wait(api)["run_attempt"], 2)
        self.assertEqual(api.run_calls, 2)

    def test_pagination_preserves_filters_and_finds_newer_run(self):
        api = provenance.GitHubApi()
        first_page = [ci_run(1)] + [ci_run(i, head_sha=OTHER_SHA) for i in range(2, 101)]
        pages = [
            {"total_count": 101, "workflow_runs": first_page},
            {"total_count": 101, "workflow_runs": [ci_run(101, conclusion="failure")]},
        ]
        with patch.object(api, "read", side_effect=pages) as read:
            runs = api.runs(REPOSITORY, SHA)
        self.assertEqual(len(runs), 101)
        for page, invocation in enumerate(read.call_args_list, start=1):
            endpoint = urlsplit(invocation.args[0])
            self.assertEqual(endpoint.path, f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs")
            query = parse_qs(endpoint.query)
            self.assertEqual(query["branch"], ["releases"])
            self.assertEqual(query["event"], ["push"])
            self.assertEqual(query["head_sha"], [SHA])
            self.assertEqual(query["page"], [str(page)])
        with self.assertRaisesRegex(provenance.ProvenanceError, "#101.*failure"):
            self.wait(FakeApi(runs))

    def test_api_failure_does_not_log_token_or_gh_error_output(self):
        error = provenance.subprocess.CalledProcessError(
            1, ["gh", "api"], stderr="sensitive-token-must-not-be-printed"
        )
        with patch.object(provenance.subprocess, "run", side_effect=error):
            with self.assertRaises(provenance.ProvenanceError) as raised:
                provenance.GitHubApi().read("repos/example/actions/workflows/ci.yml")
        self.assertNotIn("sensitive-token", str(raised.exception))


class EventTests(unittest.TestCase):
    def verify(self, event_name: str, event: dict, api: FakeApi | None = None) -> str:
        with redirect_stdout(io.StringIO()):
            return provenance.verify_event(
                event_name, event, REPOSITORY, "refs/tags/v1.2.3", SHA,
                api or FakeApi([ci_run()]),
            )

    def event(self, **changes: object) -> dict:
        return {"repository": {"full_name": REPOSITORY}} | changes

    def test_tag_requires_ancestry_and_same_sha_ci(self):
        with patch.object(provenance, "git", return_value=SHA) as git:
            self.assertEqual(self.verify("push", self.event()), SHA)
        self.assertIn(
            call("merge-base", "--is-ancestor", SHA, "refs/remotes/origin/releases"),
            git.call_args_list,
        )

    def test_tag_mismatch_or_non_ancestor_rejects_before_ci(self):
        api = FakeApi([ci_run()])
        with patch.object(provenance, "git", side_effect=[SHA, SHA, OTHER_SHA]):
            with self.assertRaisesRegex(provenance.ProvenanceError, "标签目标"):
                self.verify("push", self.event(), api)
        self.assertEqual(api.workflow_calls, 0)
        with patch.object(
            provenance, "git",
            side_effect=[SHA, SHA, SHA, provenance.ProvenanceError("祖先关系失败")],
        ):
            with self.assertRaisesRegex(provenance.ProvenanceError, "祖先"):
                self.verify("push", self.event(), api)

    def test_checkout_mismatch_and_deleted_tag_reject(self):
        with patch.object(provenance, "git", side_effect=[SHA, OTHER_SHA]):
            with self.assertRaisesRegex(provenance.ProvenanceError, "工作区"):
                self.verify("push", self.event())
        with patch.object(provenance, "git", return_value=SHA):
            with self.assertRaisesRegex(provenance.ProvenanceError, "现存"):
                self.verify("push", self.event(deleted=True))

    def test_workflow_run_failure_and_cancel_reject(self):
        for conclusion in ("failure", "cancelled"):
            api = FakeApi()
            with self.subTest(conclusion=conclusion), self.assertRaisesRegex(
                provenance.ProvenanceError, "未成功"
            ):
                self.verify("workflow_run", self.event(workflow_run=ci_run(conclusion=conclusion)), api)
            self.assertEqual(api.workflow_calls, 0)

    def test_workflow_run_rejects_other_events_branches_workflows_and_forks(self):
        invalid_runs = [
            ci_run(event="pull_request"), ci_run(head_branch="dev"),
            ci_run(workflow_id=99),
            ci_run(head_repository={"full_name": "fork/chenxing-auth"}),
        ]
        for run in invalid_runs:
            with self.subTest(run=run), self.assertRaisesRegex(
                provenance.ProvenanceError, "只接受"
            ):
                self.verify("workflow_run", self.event(workflow_run=run))

    def test_workflow_run_uses_ci_head_not_default_branch_context(self):
        run = ci_run(head_sha=OTHER_SHA)
        with patch.object(provenance, "git") as git:
            self.assertEqual(
                self.verify("workflow_run", self.event(workflow_run=run), FakeApi([run])),
                OTHER_SHA,
            )
        git.assert_not_called()

    def test_repository_and_unsupported_event_reject(self):
        with self.assertRaisesRegex(provenance.ProvenanceError, "仓库"):
            self.verify("push", {"repository": {"full_name": "fork/auth"}})
        with self.assertRaisesRegex(provenance.ProvenanceError, "不支持"):
            self.verify("pull_request", self.event())

    def test_manual_build_does_not_require_release_ci(self):
        api = FakeApi()
        with patch.object(provenance, "git", return_value=SHA):
            self.assertEqual(self.verify("workflow_dispatch", self.event(), api), SHA)
        self.assertEqual(api.workflow_calls, 0)


class WorkflowWiringTests(unittest.TestCase):
    def test_every_build_and_publish_job_uses_verified_sha(self):
        workflow = (Path(__file__).parents[1] / "workflows" / "build.yml").read_text("utf-8")
        for job in ("web", "rust-binaries", "container", "release"):
            body = re.search(
                rf"^  {job}:\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)",
                workflow, re.MULTILINE | re.DOTALL,
            ).group(1)
            with self.subTest(job=job):
                self.assertIn("needs.verify-provenance.outputs.valid == 'true'", body)
                self.assertIn("ref: ${{ needs.verify-provenance.outputs.sha }}", body)
                self.assertRegex(body, r"needs:.*verify-provenance")
                if job == "release":
                    self.assertIn("github.event_name == 'push'", body)
                    self.assertIn("startsWith(github.ref, 'refs/tags/v')", body)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("python3 .github/scripts/verify_release_provenance.py", workflow)


if __name__ == "__main__":
    unittest.main()
