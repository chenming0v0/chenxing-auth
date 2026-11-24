#!/usr/bin/env python3
"""使用 Docker mock 验证升级事务；由部署契约调用，不连接 Docker daemon。"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OLD_VERSION = "v0.0.0"
NEW_VERSION = "v0.0.1"
OLD_IMAGE = f"ghcr.io/chenming0v0/chenxing-auth:{OLD_VERSION}"
NEW_IMAGE = f"ghcr.io/chenming0v0/chenxing-auth:{NEW_VERSION}"
OLD_ID = "sha256:" + "1" * 64
NEW_ID = "sha256:" + "2" * 64
TAG_ID = "sha256:" + "3" * 64
ENVIRONMENT = {
    "CHENXING_RELEASE_VERSION": OLD_VERSION,
    "CHENXING_IMAGE": OLD_IMAGE,
    "COMPOSE_PROJECT_NAME": "chenxing-auth",
    "POSTGRES_IMAGE": "postgres:16-alpine",
    "REDIS_IMAGE": "redis:7-alpine",
    "POSTGRES_DB": "chenxing_auth",
    "POSTGRES_USER": "existing_owner",
    "POSTGRES_PASSWORD": "owner-password=with-equals",
    "POSTGRES_RUNTIME_USER": "existing_runtime",
    "POSTGRES_RUNTIME_PASSWORD": "runtime-password",
    "DATABASE_URL": "postgres://existing-runtime-url",
    "MIGRATION_DATABASE_URL": "postgres://existing-migration-url",
    "AUTH_ENCRYPTION_KEY": "existing-encryption-key",
    "AUTH_ENCRYPTION_KEYS": "kid=custom:existing-key-ring",
    "AUTH_ENCRYPTION_ACTIVE_KID": "custom",
    "REDIS_NAMESPACE": "existing_namespace",
    "ADMIN_TOKEN": "existing-admin-token",
    "COOKIE_SECURE": "true",
    "APP_PORT": "8080",
    "CUSTOM_SETTING": "original-value",
}

MOCK_DOCKER = r'''from pathlib import Path
import json
import os
import sys

root = Path(@WORK_DIR@)
scenario = json.loads((root / "scenario.json").read_text())
old_id = "sha256:" + "1" * 64
new_id = "sha256:" + "2" * 64
tag_id = "sha256:" + "3" * 64
new_image = "ghcr.io/chenming0v0/chenxing-auth:v0.0.1"
state_file = root / "image"

def env_values(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line and not line.startswith("#"))

args = sys.argv[1:]
record = {"kind": args[0], "args": args, "disk": env_values(root / "deployment" / ".env")}
if args[0] == "compose":
    config = env_values(Path(args[2]))
    action = args[5:]
    image = os.environ.get("CHENXING_IMAGE", config["CHENXING_IMAGE"])
    record.update(action=action, image=image, version=config["CHENXING_RELEASE_VERSION"])
    record["forwarded"] = {key: os.environ[key] for key in (
        "ADMIN_TOKEN", "AUTH_ENCRYPTION_KEY", "DATABASE_URL", "MIGRATION_DATABASE_URL",
        "COOKIE_SECURE", "OAUTH_PROVIDER_LOOPBACK_ENABLED", "CHENXING_RELEASE_VERSION",
    ) if key in os.environ}
with (root / "calls.jsonl").open("a") as output:
    output.write(json.dumps(record) + "\n")

if args[0] == "inspect":
    print(old_id)
elif args[:2] == ["image", "inspect"]:
    if not scenario["old_image_present"] and not (root / "old-pulled").exists():
        sys.exit(1)
    print(tag_id)
elif args[0] == "pull":
    if args[1].endswith(":v0.0.0"):
        (root / "old-pulled").write_text("available")
    if args[1] == new_image and scenario["name"] == "pull-fail":
        sys.exit(1)
elif args[0] == "exec":
    if scenario["name"] == "candidate-fail":
        sys.exit(1)
elif args[0] == "compose":
    if action == ["ps", "--all", "--quiet", "app"]:
        if scenario["container_present"]:
            print("previous-app-container")
    elif action == ["config", "--quiet"] and scenario["name"] == "config-fail":
        sys.exit(1)
    elif action == ["run", "--rm", "migrate"]:
        if scenario["name"] == "migration-fail":
            sys.exit(1)
    elif action[0] == "up" and action[-1] == "app":
        if image == new_image:
            state_file.write_text(new_id)
            if scenario["name"] == "up-fail":
                sys.exit(1)
        else:
            if scenario["name"] == "rollback-up-fail":
                sys.exit(1)
            state_file.write_text(image)
    elif action[:3] == ["exec", "-T", "app"]:
        image_id = state_file.read_text()
        if image_id == new_id and scenario["name"] in (
            "ready-fail", "rollback-up-fail", "rollback-ready-fail",
        ):
            sys.exit(1)
        if image_id != new_id and scenario["name"] == "rollback-ready-fail":
            sys.exit(1)
'''


def env_values(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if line)


def exercise(
    name: str, *, container_present: bool = True, old_image_present: bool = True,
    crlf: bool = False,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="chenxing-upgrade-") as temporary:
        work = Path(temporary)
        deployment = work / "deployment"
        fake_bin = work / "bin"
        deployment.mkdir()
        fake_bin.mkdir()
        shutil.copyfile(ROOT / "update.sh", deployment / "update.sh")
        shutil.copyfile(ROOT / "deploy" / "compose.yml", deployment / "compose.yml")
        separator = "\r\n" if crlf else "\n"
        original = (separator.join(f"{key}={value}" for key, value in ENVIRONMENT.items()) + separator).encode()
        (deployment / ".env").write_bytes(original)
        (work / "scenario.json").write_text(json.dumps({
            "name": name, "container_present": container_present,
            "old_image_present": old_image_present,
        }))
        (work / "image").write_text(OLD_ID)
        (work / "docker.py").write_text(
            MOCK_DOCKER.replace("@WORK_DIR@", repr(str(work))), encoding="utf-8", newline="\n",
        )
        python = shlex.quote(sys.executable.replace("\\", "/"))
        mock_script = shlex.quote(str(work / "docker.py").replace("\\", "/"))
        (fake_bin / "docker").write_text(
            f'#!/usr/bin/env bash\nexec {python} {mock_script} "$@"\n', encoding="utf-8", newline="\n",
        )
        # 就绪失败需要走完轮询，mock sleep 避免测试真正等待两分钟。
        (fake_bin / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n")
        if name == "commit-fail":
            (fake_bin / "mv").write_text(
                '#!/usr/bin/env bash\nargs=("$@")\n'
                'if [[ "${args[-2]}" == *.env.upgrade.* && "${args[-1]}" == */.env ]]; then exit 1; fi\n'
                'exec /usr/bin/mv "$@"\n', encoding="utf-8", newline="\n",
            )
        for binary in fake_bin.iterdir():
            binary.chmod(0o755)
        environment = os.environ | {
            "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
            "CHENXING_RELEASE_VERSION": NEW_VERSION,
            "CHENXING_IMAGE": "ignored-parent-image",
            "AUTH_ENCRYPTION_KEY": "ignored-parent-key",
            "ADMIN_TOKEN": "ignored-parent-token",
            "DATABASE_URL": "ignored-parent-database-url",
            "MIGRATION_DATABASE_URL": "ignored-parent-migration-url",
            "COOKIE_SECURE": "false",
            "OAUTH_PROVIDER_LOOPBACK_ENABLED": "true",
        }
        result = subprocess.run(
            ["bash", str(deployment / "update.sh").replace("\\", "/")],
            env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        return {
            "status": result.returncode,
            "output": result.stdout + result.stderr,
            "original": original,
            "environment": (deployment / ".env").read_bytes(),
            "image": (work / "image").read_text(),
            "calls": [json.loads(line) for line in (work / "calls.jsonl").read_text().splitlines()],
            "files": sorted(path.name for path in deployment.iterdir()),
            "mode": (deployment / ".env").stat().st_mode & 0o777,
        }


class UpgradeRollbackTests(unittest.TestCase):
    def app_calls(self, result: dict) -> list[dict]:
        return [call for call in result["calls"] if call.get("action", [None])[0] == "up"
                and call["action"][-1] == "app"]

    def assert_old_environment(self, result: dict) -> None:
        self.assertEqual(result["environment"], result["original"], result["output"])
        self.assertEqual(result["files"], [".env", "compose.yml", "update.sh"])

    def assert_recovered(self, result: dict, expected_image: str = OLD_ID) -> None:
        self.assertNotEqual(result["status"], 0, result["output"])
        self.assert_old_environment(result)
        self.assertEqual(result["image"], expected_image, result["output"])
        self.assertIn("已恢复旧应用并通过就绪检查", result["output"])
        self.assertIn("数据库迁移已保留", result["output"])
        calls = self.app_calls(result)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["image"], expected_image)
        self.assertEqual(calls[1]["version"], OLD_VERSION)
        for call in calls:
            self.assertEqual(call["action"], ["up", "-d", "--no-deps", "--pull", "never", "app"])
        migrations = [call for call in result["calls"] if call.get("action") == ["run", "--rm", "migrate"]]
        self.assertEqual(len(migrations), 1)
        self.assertEqual(migrations[0]["image"], NEW_IMAGE)

    def test_success_commits_version_only_after_new_app_ready(self):
        result = exercise("success")
        self.assertEqual(result["status"], 0, result["output"])
        self.assertEqual(result["image"], NEW_ID)
        expected = ENVIRONMENT | {"CHENXING_RELEASE_VERSION": NEW_VERSION, "CHENXING_IMAGE": NEW_IMAGE}
        self.assertEqual(env_values(result["environment"].decode()), expected)
        self.assertEqual(result["files"], [".env", "compose.yml", "update.sh"])
        app_calls = self.app_calls(result)
        self.assertEqual(len(app_calls), 1)
        self.assertEqual(app_calls[0]["version"], NEW_VERSION)
        self.assertEqual(app_calls[0]["disk"], ENVIRONMENT)
        for call in result["calls"]:
            if call["kind"] == "compose":
                self.assertEqual(call["forwarded"], {}, call)
                if call["action"] != ["ps"]:
                    self.assertEqual(call["disk"], ENVIRONMENT)
        migration = next(call for call in result["calls"] if call.get("action") == ["run", "--rm", "migrate"])
        self.assertEqual(migration["image"], NEW_IMAGE)
        self.assertEqual(migration["version"], NEW_VERSION)
        if os.name != "nt":
            self.assertEqual(result["mode"], 0o600)

    def test_pull_failure_does_not_change_old_anchor_or_switch_app(self):
        result = exercise("pull-fail")
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(result["image"], OLD_ID)
        self.assertEqual(self.app_calls(result), [])
        self.assertFalse(any(call.get("action") == ["run", "--rm", "migrate"] for call in result["calls"]))

    def test_config_failure_does_not_change_old_anchor(self):
        result = exercise("config-fail")
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(self.app_calls(result), [])

    def test_migration_failure_preserves_old_app_and_crlf_environment(self):
        result = exercise("migration-fail", crlf=True)
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(result["image"], OLD_ID)
        self.assertEqual(self.app_calls(result), [])
        self.assertIn("旧应用未切换，版本和镜像记录未改变", result["output"])

    def test_partial_up_failure_restores_old_image(self):
        self.assert_recovered(exercise("up-fail"))

    def test_candidate_failure_keeps_the_original_running_container(self):
        result = exercise("candidate-fail")
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(result["image"], OLD_ID)
        self.assertEqual(self.app_calls(result), [])
        self.assertIn("旧应用未切换，版本记录未改变", result["output"])

    def test_readiness_failure_restores_actual_image_not_mutable_tag(self):
        self.assert_recovered(exercise("ready-fail"))

    def test_environment_commit_failure_also_rolls_back(self):
        self.assert_recovered(exercise("commit-fail"))

    def test_without_old_container_records_local_image_before_switch(self):
        self.assert_recovered(exercise("ready-fail", container_present=False), TAG_ID)

    def test_interrupted_install_prepares_recoverable_old_image(self):
        result = exercise("ready-fail", container_present=False, old_image_present=False)
        self.assert_recovered(result, TAG_ID)
        old_pull = next(call for call in result["calls"] if call["args"] == ["pull", OLD_IMAGE])
        self.assertEqual(old_pull["disk"], ENVIRONMENT)

    def test_rollback_up_failure_reports_failure_truthfully(self):
        result = exercise("rollback-up-fail")
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(result["image"], NEW_ID)
        self.assertIn("自动回滚失败：旧应用容器未能恢复", result["output"])
        self.assertNotIn("已恢复旧应用并通过就绪检查", result["output"])

    def test_rollback_readiness_failure_does_not_claim_old_app_ready(self):
        result = exercise("rollback-ready-fail")
        self.assertNotEqual(result["status"], 0)
        self.assert_old_environment(result)
        self.assertEqual(result["image"], OLD_ID)
        self.assertIn("自动回滚失败：旧应用未通过就绪检查", result["output"])
        self.assertNotIn("已恢复旧应用并通过就绪检查", result["output"])


if __name__ == "__main__":
    unittest.main()
