use super::{BUILD_WORKFLOW, CI_WORKFLOW, TEST_RUNNER_CONTRACT_SCRIPT};

fn workflow_job(workflow: &str, name: &str) -> String {
    let workflow = workflow.replace("\r\n", "\n");
    let marker = format!("\n  {name}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow is missing job: {name}"))
        + 1;
    let rest = &workflow[start..];
    let end = rest
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let candidate = &rest[offset + 1..];
            let line = candidate.lines().next()?;
            (!line.starts_with("    ") && line.ends_with(':')).then_some(offset)
        })
        .unwrap_or(rest.len());
    rest[..end].to_owned()
}

fn workflow_top_level_permissions(workflow: &str) -> String {
    let workflow = workflow.replace("\r\n", "\n");
    workflow
        .split_once("\npermissions:\n")
        .and_then(|(_, rest)| rest.split_once("\njobs:\n"))
        .map(|(permissions, _)| permissions.to_owned())
        .expect("workflow must declare top-level permissions before jobs")
}

/// 返回 workflow 里 `action@<40 位小写十六进制 commit SHA>` 的实际字面量。
///
/// #699 把所有 action 固定为 commit SHA，`@v4` 这类可变标签已不存在；但把新 SHA 写成
/// 字面量会让每次 dependabot 升级都被迫改测试。所以这里只断言「该 action 仍被使用，且
/// 形态是 SHA 固定」。全局 pin 校验由 `.github/scripts/verify_action_pins.py` 在 CI 里
/// 负责，本函数不重复实现。
fn pinned_action_reference(workflow: &str, action: &str) -> String {
    let prefix = format!("{action}@");
    for (offset, _) in workflow.match_indices(prefix.as_str()) {
        let rest = &workflow[offset + prefix.len()..];
        let sha: String = rest.chars().take(40).collect();
        let is_sha = sha.chars().count() == 40
            && sha
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase());
        // 后面紧跟的必须不是字母数字，否则 40 个字符只是更长引用的前缀。
        let ends_here = !rest
            .chars()
            .nth(40)
            .is_some_and(|character| character.is_ascii_alphanumeric());
        if is_sha && ends_here {
            return format!("{prefix}{sha}");
        }
    }
    panic!("workflow must use {action} pinned to a 40-character commit SHA");
}

#[test]
fn release_workflow_publishes_versioned_archives_and_checksums() {
    // 这两个 action 必须仍被使用，并且按 commit SHA 固定，而不是可变的 `@v2` / `@v4`。
    pinned_action_reference(BUILD_WORKFLOW, "actions/download-artifact");
    pinned_action_reference(BUILD_WORKFLOW, "softprops/action-gh-release");
    for marker in [
        "SHA256SUMS",
        "(cd dist && sha256sum * > SHA256SUMS)",
        "Verify downloaded release assets",
        "gh release download",
        "--repo \"${GITHUB_REPOSITORY}\"",
        "sha256sum -c SHA256SUMS",
        "startsWith(github.ref, 'refs/tags/v')",
        "github.event_name == 'push'",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing marker: {marker}"
        );
    }
    // 安装链已回归 raw 分支四文件契约：发布资产不再打包安装器或清单。
    for stale in ["chenxing-auth-manage.sh", "chenxing-auth-release.env"] {
        assert!(
            !BUILD_WORKFLOW.contains(stale),
            "release workflow must not package installer asset: {stale}"
        );
    }
}

#[test]
fn build_workflow_scopes_write_permissions_and_drops_checkout_credentials() {
    let defaults = workflow_top_level_permissions(BUILD_WORKFLOW);
    assert!(defaults.contains("  contents: read"));
    assert!(defaults.contains("  actions: read"));
    assert!(!defaults.contains("write"));

    let release = workflow_job(BUILD_WORKFLOW, "release");
    assert!(release.contains("permissions:\n      contents: write"));
    assert!(!release.contains("packages: write"));

    let container = workflow_job(BUILD_WORKFLOW, "container");
    assert!(container.contains("permissions:\n      contents: read\n      packages: write"));
    assert!(!container.contains("contents: write"));

    for name in ["verify-provenance", "web", "rust-binaries"] {
        let job = workflow_job(BUILD_WORKFLOW, name);
        assert!(
            !job.contains("contents: write") && !job.contains("packages: write"),
            "ordinary build job {name} must not receive write permissions"
        );
    }

    let pinned_checkout = pinned_action_reference(BUILD_WORKFLOW, "actions/checkout");
    for name in ["web", "rust-binaries", "container"] {
        let job = workflow_job(BUILD_WORKFLOW, name);
        assert!(
            job.contains(pinned_checkout.as_str()),
            "{name} must check out the repository with a SHA-pinned actions/checkout"
        );
        assert!(
            job.contains("persist-credentials: false"),
            "repository code checkout in {name} must not persist the job token"
        );
    }
}

#[test]
fn publish_workflow_builds_release_tags_without_waiting_for_ci() {
    assert!(BUILD_WORKFLOW.contains("actions: read"));
    assert!(BUILD_WORKFLOW.contains("manual-${{ github.sha }}"));
    assert!(!BUILD_WORKFLOW.contains("type=ref,event=branch"));
    assert!(BUILD_WORKFLOW.contains("github.event_name == 'workflow_dispatch'"));
    assert!(
        BUILD_WORKFLOW
            .contains("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')")
    );
    assert!(BUILD_WORKFLOW.contains("github.event.workflow_run.head_sha"));
    assert!(BUILD_WORKFLOW.contains("merge-base --is-ancestor"));
    assert!(!BUILD_WORKFLOW.contains("actions/workflows/ci.yml/runs"));
    assert!(!BUILD_WORKFLOW.contains(".workflow_runs[]"));
    assert!(BUILD_WORKFLOW.contains("github.event_name == 'workflow_run'"));
    assert!(!BUILD_WORKFLOW.contains("github.ref == 'refs/heads/dev'"));
    assert!(!BUILD_WORKFLOW.contains("github.event_name != 'workflow_run'\n"));
}

#[test]
fn native_release_archives_ship_and_verify_the_matching_web_bundle() {
    let unix_at = BUILD_WORKFLOW
        .find("- name: Package Unix binary")
        .expect("Unix packaging step");
    let windows_at = BUILD_WORKFLOW
        .find("- name: Package Windows binary")
        .expect("Windows packaging step");
    let pinned_upload = pinned_action_reference(BUILD_WORKFLOW, "actions/upload-artifact");
    let upload_step = format!("- uses: {pinned_upload}");
    let upload_at = BUILD_WORKFLOW[windows_at..]
        .find(upload_step.as_str())
        .map(|offset| windows_at + offset)
        .expect("native archive upload step");
    let unix_step = &BUILD_WORKFLOW[unix_at..windows_at];
    let windows_step = &BUILD_WORKFLOW[windows_at..upload_at];
    for marker in [
        "cp -R web/dist \"$package_root/web/dist\"",
        "chenxing-auth web/dist",
    ] {
        assert!(
            unix_step.contains(marker),
            "Unix archive missing marker: {marker}"
        );
    }
    for marker in [
        "Copy-Item `",
        "-LiteralPath \"web/dist\"",
        "Join-Path $packageRoot \"web\"",
        "Join-Path $packageRoot \"*\"",
    ] {
        assert!(
            windows_step.contains(marker),
            "Windows archive missing marker: {marker}"
        );
    }
    for marker in [
        "Smoke test downloaded native archives",
        "verified-download/chenxing-auth-*.tar.gz",
        "verified-download/chenxing-auth-*.zip",
        "tar -xzf",
        "unzip -q",
        "web/dist/index.html",
        "release archive is missing referenced asset",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release smoke check missing marker: {marker}"
        );
    }
}

#[test]
fn ci_validates_the_remote_installer_without_weakening_coverage() {
    for marker in [
        "bash -n manage.sh",
        "bash -n install.sh",
        "bash -n update.sh",
        "bash test_sh/deployment_contract.sh",
        "config --quiet",
        "--fail-under-lines 75",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI workflow is missing deployment or coverage marker: {marker}"
        );
    }
}

#[test]
fn test_runner_missing_tools_fail_closed_without_running_tests() {
    for marker in [
        "PATH=\"$temp_root/empty-path\"",
        "MODE=filter",
        "NEXTEST=0",
        "assert_failed_phase \"测试\" phase_test",
        "assert_failed_phase \"覆盖检查\" phase_coverage",
        "assert_failed_phase \"依赖审计\" phase_audit",
    ] {
        assert!(
            TEST_RUNNER_CONTRACT_SCRIPT.contains(marker),
            "test runner contract missing marker: {marker}"
        );
    }
    for marker in [
        "bash -n test_sh/test_runner_contract.sh",
        "bash test_sh/test_runner_contract.sh",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI missing test runner contract marker: {marker}"
        );
    }
}

#[test]
fn release_workflow_keeps_all_supported_targets() {
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(target),
            "target is missing: {target}"
        );
    }
}

#[test]
fn release_workflow_builds_web_once_and_reuses_it() {
    for marker in [
        "name: Build embedded web",
        "name: web-dist",
        "needs: [verify-provenance, web]",
        "path: web/dist",
        "CHENXING_USE_PREBUILT_WEB",
        "Accept prebuilt embedded web",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing web reuse marker: {marker}"
        );
    }

    let web_build_steps = BUILD_WORKFLOW
        .matches("npm ci --prefix web && npm run build --prefix web")
        .count();
    assert_eq!(
        web_build_steps, 1,
        "embedded web must be built exactly once in the release workflow"
    );
}

#[test]
fn release_workflow_builds_linux_arm_natively_and_packages_containers() {
    for marker in [
        "ubuntu-24.04-arm",
        "rust:1.94-bookworm",
        "Dockerfile.runtime",
        "container-binaries/amd64",
        "container-binaries/arm64",
        "binary-x86_64-unknown-linux-gnu",
        "binary-aarch64-unknown-linux-gnu",
        "platforms: linux/amd64,linux/arm64",
        "ldd -r",
        "Smoke test final container per architecture",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing container packaging marker: {marker}"
        );
    }

    assert!(
        !BUILD_WORKFLOW.contains("builder: cross"),
        "Linux arm64 must build natively instead of through cross/QEMU cargo"
    );
    assert!(
        BUILD_WORKFLOW.contains("file: Dockerfile.runtime"),
        "container job must package with Dockerfile.runtime"
    );
}
