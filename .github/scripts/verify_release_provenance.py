#!/usr/bin/env python3
"""将发布来源绑定到同仓库、同提交的 releases push CI。"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode


CI_PATH = ".github/workflows/ci.yml"
CI_BRANCH = "releases"
WAIT_SECONDS = 1800
POLL_SECONDS = 30
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ProvenanceError(Exception):
    """来源不可信或尚未得到成功的质量检查结果。"""


class GitHubApi:
    def read(self, endpoint: str) -> dict[str, Any]:
        # gh 从 GH_TOKEN 读取令牌，不把凭据放进参数或错误日志。
        try:
            result = subprocess.run(
                ["gh", "api", "--method", "GET", endpoint],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            raise ProvenanceError(
                "无法读取 GitHub CI 记录，请检查 actions:read 权限及 API 可用性。"
            ) from None
        return json.loads(result.stdout)

    def workflow(self, repository: str) -> dict[str, Any]:
        workflow = self.read(f"repos/{repository}/actions/workflows/ci.yml")
        if workflow.get("path") != CI_PATH or workflow.get("name") != "CI":
            raise ProvenanceError("发布质量门禁必须使用 .github/workflows/ci.yml。")
        return workflow

    def runs(self, repository: str, sha: str) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        page = 1
        while True:
            query = urlencode(
                {
                    "branch": CI_BRANCH,
                    "event": "push",
                    "head_sha": sha,
                    "exclude_pull_requests": "true",
                    "per_page": 100,
                    "page": page,
                }
            )
            response = self.read(
                f"repos/{repository}/actions/workflows/ci.yml/runs?{query}"
            )
            batch = response["workflow_runs"]
            runs.extend(batch)
            if not batch or len(runs) >= response["total_count"]:
                return runs
            page += 1


def matches_ci(
    run: dict[str, Any], repository: str, sha: str, workflow_id: int
) -> bool:
    return (
        run.get("workflow_id") == workflow_id
        and run.get("event") == "push"
        and run.get("head_branch") == CI_BRANCH
        and run.get("head_sha") == sha
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
    )


def wait_for_ci(
    api: GitHubApi,
    repository: str,
    sha: str,
    workflow_id: int,
    *,
    timeout: float = WAIT_SECONDS,
    interval: float = POLL_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    deadline = clock() + timeout
    last_message = ""
    while True:
        candidates = [
            run
            for run in api.runs(repository, sha)
            if matches_ci(run, repository, sha, workflow_id)
        ]
        if candidates:
            # 同一 SHA 可能再次 push 或重跑；只采用最新运行，不能用旧成功盖过新失败。
            latest = max(
                candidates,
                key=lambda run: (
                    run["run_number"], run["id"], run.get("run_attempt", 1)
                ),
            )
            if latest["status"] == "completed":
                if latest.get("conclusion") != "success":
                    raise ProvenanceError(
                        f"同提交 releases push CI #{latest['id']} "
                        f"结果为 {latest.get('conclusion')}，拒绝发布。"
                    )
                print(f"已确认 releases push CI #{latest['id']} 成功：{sha}")
                return latest
            message = f"等待 releases push CI #{latest['id']}：{latest['status']}"
        else:
            message = f"等待同提交的 releases push CI 记录：{sha}"
        if message != last_message:
            print(message, flush=True)
            last_message = message
        remaining = deadline - clock()
        if remaining <= 0:
            raise ProvenanceError("等待同提交 releases push CI 超时，拒绝发布。")
        sleep(min(interval, remaining))


def git(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.SubprocessError):
        raise ProvenanceError("无法确认标签目标或 releases 分支的提交祖先关系。") from None
    return result.stdout.strip()


def verify_event(
    event_name: str,
    event: dict[str, Any],
    repository: str,
    ref: str,
    event_sha: str,
    api: GitHubApi,
) -> str:
    if event.get("repository", {}).get("full_name") != repository:
        raise ProvenanceError("事件仓库与当前发布仓库不一致。")
    if event_name == "workflow_run":
        run = event["workflow_run"]
        if run.get("conclusion") != "success":
            raise ProvenanceError("触发构建的 CI 未成功，拒绝发布。")
        sha = run.get("head_sha", "")
        workflow_id = api.workflow(repository)["id"]
        if not SHA_RE.fullmatch(sha) or not matches_ci(
            run, repository, sha, workflow_id
        ):
            raise ProvenanceError("只接受本仓库 releases 分支 push 触发的 CI。")
        wait_for_ci(api, repository, sha, workflow_id)
        return sha
    if event_name not in {"workflow_dispatch", "push"}:
        raise ProvenanceError(f"不支持的发布事件：{event_name}")
    if not SHA_RE.fullmatch(event_sha):
        raise ProvenanceError("发布事件缺少有效提交 SHA。")
    sha = git("rev-parse", "--verify", f"{event_sha}^{{commit}}")
    if git("rev-parse", "HEAD") != sha:
        raise ProvenanceError("工作区提交与发布事件目标不一致。")
    if event_name == "workflow_dispatch":
        # 手动构建只发布 manual-SHA 镜像，不进入版本标签或 Release 路径。
        return sha
    if not ref.startswith("refs/tags/v") or event.get("deleted"):
        raise ProvenanceError("push 发布仅接受现存的 v* 标签。")
    if git("rev-parse", "--verify", f"{ref}^{{commit}}") != sha:
        raise ProvenanceError("标签目标与本次 push 的提交不一致。")
    git("merge-base", "--is-ancestor", sha, "refs/remotes/origin/releases")
    workflow_id = api.workflow(repository)["id"]
    wait_for_ci(api, repository, sha, workflow_id)
    return sha


def main() -> int:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        sha = verify_event(
            os.environ["GITHUB_EVENT_NAME"],
            event,
            os.environ["GITHUB_REPOSITORY"],
            os.environ["GITHUB_REF"],
            os.environ["GITHUB_SHA"],
            GitHubApi(),
        )
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"valid=true\nsha={sha}\n")
    except (ProvenanceError, OSError, ValueError, KeyError) as error:
        print(f"发布来源校验失败：{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
