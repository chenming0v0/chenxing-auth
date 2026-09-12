use super::{
    BUILD_WORKFLOW, CONFIG_CONSTRUCTION_MODULE, DOCKERFILE, DOCKERIGNORE, RUNTIME_DOCKERFILE,
    STATE_MODULE, STATIC_FILES_MODULE, WEB_DIST_IMAGE_PATH, WEB_DIST_MODULE,
};
use std::path::Path;

/// 取出 HTML 里 `src="/..."` / `href="/..."` 形式的根绝对引用。
///
/// 只认根绝对路径：相对引用和外部 URL 不受 `WEB_DIST_DIR` 布局影响。
fn root_absolute_references(html: &str) -> Vec<String> {
    let mut references = Vec::new();
    for attribute in ["src=\"", "href=\""] {
        let mut rest = html;
        while let Some(start) = rest.find(attribute) {
            rest = &rest[start + attribute.len()..];
            let Some(end) = rest.find('"') else { break };
            let value = &rest[..end];
            rest = &rest[end + 1..];
            if value.starts_with('/') && !value.starts_with("//") {
                references.push(value.to_owned());
            }
        }
    }
    references
}

#[test]
fn runtime_dockerfile_only_packages_prebuilt_artifacts() {
    for marker in [
        "COPY container-binaries/${TARGETARCH}/chenxing-auth /usr/local/bin/chenxing-auth",
        "COPY container-web-dist /usr/local/share/chenxing-auth/web/dist",
        "ARG TARGETARCH",
        "ENTRYPOINT [\"/usr/local/bin/chenxing-auth\"]",
    ] {
        assert!(
            RUNTIME_DOCKERFILE.contains(marker),
            "runtime Dockerfile is missing marker: {marker}"
        );
    }
    assert!(
        !RUNTIME_DOCKERFILE.contains("cargo build"),
        "runtime Dockerfile must not compile Rust"
    );
    assert!(
        !RUNTIME_DOCKERFILE.contains("npm "),
        "runtime Dockerfile must not build the frontend"
    );
}

#[test]
fn source_dockerfile_still_supports_local_compose_builds() {
    for marker in [
        "FROM node:22-bookworm-slim AS web-builder",
        "FROM rust:1.94-bookworm AS builder",
        "COPY build.rs build_logic.rs ./",
        "RUN cargo build --release --locked",
        "COPY --from=builder /build/target/release/chenxing-auth /usr/local/bin/chenxing-auth",
    ] {
        assert!(
            DOCKERFILE.contains(marker),
            "source Dockerfile is missing marker: {marker}"
        );
    }
}

/// Issue #272：两条生产镜像路径都必须带上 `web/dist`，并指向同一个 `WEB_DIST_DIR`。
///
/// 二进制只在编译期内嵌 `index.html`，它引用的 JS/CSS/字体由 `ServeDir` 从磁盘读取。
/// 镜像的 WORKDIR 是可变状态目录，相对路径 `web/dist` 必然落空，所以路径必须由
/// `WEB_DIST_DIR` 显式给出，且两条路径给出同一个值——否则一条路径能用、另一条 404。
#[test]
fn both_production_images_ship_the_web_bundle_at_the_same_web_dist_dir() {
    assert!(
        WEB_DIST_IMAGE_PATH.starts_with('/'),
        "the image bundle path must be absolute: WORKDIR is the mutable state \
         directory, so a relative path would resolve outside the bundle"
    );

    let env_line = format!("WEB_DIST_DIR={WEB_DIST_IMAGE_PATH}");
    for (name, dockerfile, copy) in [
        (
            "Dockerfile",
            DOCKERFILE,
            format!("COPY --from=builder /build/web/dist {WEB_DIST_IMAGE_PATH}"),
        ),
        (
            "Dockerfile.runtime",
            RUNTIME_DOCKERFILE,
            format!("COPY container-web-dist {WEB_DIST_IMAGE_PATH}"),
        ),
    ] {
        assert!(
            dockerfile.contains(&copy),
            "{name} must ship the frontend bundle into the runtime image: {copy}"
        );
        assert!(
            dockerfile.contains(&env_line),
            "{name} must point WEB_DIST_DIR at the shipped bundle: {env_line}"
        );
        assert!(
            dockerfile.contains("WORKDIR /var/lib/chenxing-auth"),
            "{name} keeps WORKDIR on mutable state, which is why WEB_DIST_DIR is required"
        );
    }
}

/// Issue #272 / #303：`WEB_DIST_DIR` 必须是服务端读取静态资源的唯一入口，
/// 且在启动期解析完毕。
///
/// 请求期解析的后果是配置错误只能表现为 404，最坏的一种是把整个工作目录当静态根，
/// 把 `.env` 和私钥暴露成可下载文件；镜像里 WORKDIR 正是密钥目录的父级。
#[test]
fn runtime_reads_the_bundle_only_through_web_dist_dir() {
    assert!(
        CONFIG_CONSTRUCTION_MODULE.contains("env::var(WEB_DIST_DIR_ENV)"),
        "the served directory must come from WEB_DIST_DIR"
    );
    assert!(
        STATIC_FILES_MODULE.contains("ServeDir::new(root.path())"),
        "static serving must use the startup-validated bundle root"
    );
    assert!(
        !STATIC_FILES_MODULE.contains("env::var"),
        "the request path must not read environment variables"
    );

    // 单二进制约束：只有 SPA shell 内嵌，资源不内嵌，所以镜像必须带目录。
    assert_eq!(
        WEB_DIST_MODULE
            .matches(
                "include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/web/dist/index.html\"))"
            )
            .count(),
        1,
        "only index.html may be embedded; assets must ship as files"
    );
    assert!(
        WEB_DIST_MODULE.contains("/web/dist/index.html\"))"),
        "the embedded shell must come from the built bundle, not from generated HTML"
    );
    assert!(
        !STATIC_FILES_MODULE.contains("include_str!"),
        "the embedded shell must have exactly one definition, in web_dist"
    );
}

/// Issue #303：静态根在启动期 canonicalize 并 fail closed，不存在回退到工作目录。
#[test]
fn the_static_root_is_canonicalized_and_validated_at_startup() {
    for marker in [
        "fs::canonicalize(&requested)",
        "WebDistError::Empty",
        "WebDistError::NotADirectory",
        "WebDistError::ForbiddenLocation",
        "WebDistError::NotABundle",
        "fn check_location(",
        "fn check_bundle(",
    ] {
        assert!(
            WEB_DIST_MODULE.contains(marker),
            "web_dist must keep the startup validation: {marker}"
        );
    }

    // 拒绝规则：文件系统根、工作目录及其被包含关系、KEY_DIRECTORY 重叠。
    for reason in [
        "the filesystem root is never a build artifact directory",
        "it is or contains the process working directory",
        "it overlaps KEY_DIRECTORY",
    ] {
        assert!(
            WEB_DIST_MODULE.contains(reason),
            "web_dist must reject this location: {reason}"
        );
    }

    // 产物根必须自证同源：index.html 在盘上，且内嵌 shell 引用的资源都能找到。
    assert!(
        WEB_DIST_MODULE.contains("format!(\"{INDEX_FILE} is missing\")"),
        "index.html must be required on disk"
    );
    assert!(
        WEB_DIST_MODULE.contains("root_absolute_references(EMBEDDED_INDEX_HTML)"),
        "the bundle must satisfy every asset the embedded shell references"
    );

    // 启动期解析必须真的被调用，且发生在监听之前。
    assert!(
        STATE_MODULE.contains("WebDistRoot::from_settings("),
        "AppState must resolve the static root at startup"
    );
    assert!(
        STATE_MODULE.contains("WebDist(#[from] WebDistError)"),
        "an invalid static root must be a startup error, not a request-time fallback"
    );
    assert!(
        !WEB_DIST_MODULE.contains("unwrap_or_else(|| DEFAULT_WEB_DIST_DIR"),
        "an empty WEB_DIST_DIR must fail closed instead of silently falling back"
    );
}

/// Issue #272：从 `index.html` 的资源引用反推镜像/上下文路径设计是否成立。
///
/// 内嵌的 shell 用 `/assets/<name>-<hash>.js` 这类根绝对路径引用资源，因此
/// `WEB_DIST_DIR` 必须正好是 dist 根目录，且整棵目录都要进镜像——只拷 `assets/`
/// 会漏掉 favicon 和字体，只拷 `index.html` 则全部资源 404。
#[test]
fn embedded_index_html_asset_references_require_the_whole_bundle_root() {
    let dist = Path::new("web/dist");
    // build.rs 在产物缺失时会 panic，所以走到测试阶段它必然存在。
    let html = std::fs::read_to_string(dist.join("index.html"))
        .expect("web/dist/index.html must exist; build.rs guarantees it");

    let references = root_absolute_references(&html);
    assert!(
        references
            .iter()
            .any(|reference| reference.ends_with(".js")),
        "the built shell must reference a hashed script: {references:?}"
    );

    let mut referenced_dirs = Vec::new();
    for reference in &references {
        let relative = reference.trim_start_matches('/');
        assert!(
            dist.join(relative).is_file(),
            "index.html references {reference}, which is missing from the bundle; \
             the image must copy the whole dist root"
        );
        let dir = relative.rsplit_once('/').map_or("", |(dir, _)| dir);
        if !referenced_dirs.contains(&dir) {
            referenced_dirs.push(dir);
        }
    }

    // 根绝对引用意味着 URL 路径直接映射到 dist 根，任何前缀化的拷贝都会错位。
    assert!(
        referenced_dirs.contains(&""),
        "root-absolute references include bundle-root files (favicon等), so \
         WEB_DIST_DIR must be the dist root itself: {referenced_dirs:?}"
    );
}

/// Issue #272：CI 上下文必须把二进制编译时用的那份 `web/dist` 一起 staged。
///
/// `index.html` 里的文件名带内容哈希，一旦镜像里的产物来自另一次构建，哈希不匹配，
/// 每个资源都会 404。所以容器 Job 必须复用 `web-dist` artifact，而不是重新构建。
#[test]
fn container_job_stages_the_same_web_bundle_the_binaries_embedded() {
    for marker in [
        "needs: [verify-provenance, web, rust-binaries]",
        "name: web-dist",
        "path: container-web-dist",
        "name: Stage container web bundle",
        "test -f container-web-dist/index.html",
        "WEB_DIST_DIR:?WEB_DIST_DIR must be set",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "container job is missing web bundle staging marker: {marker}"
        );
    }

    // 容器 Job 不得自己跑前端构建，否则产出的哈希与二进制内嵌的不一致。
    let job_at = BUILD_WORKFLOW.find("  container:").expect("container job");
    let container_job = &BUILD_WORKFLOW[job_at..];
    assert!(
        !container_job.contains("npm ci"),
        "the container job must reuse the web-dist artifact instead of rebuilding it"
    );

    let staged_at = BUILD_WORKFLOW
        .find("name: Stage container web bundle")
        .expect("web bundle staging step");
    let smoke_at = BUILD_WORKFLOW
        .find("Smoke test final container per architecture")
        .expect("smoke test step");
    assert!(
        staged_at < smoke_at,
        "the bundle must be staged before the image is built"
    );

    // 源码镜像自己构建产物，本地陈旧的 web/dist 不能进上下文顶掉它；
    // 而 CI staged 的目录必须留在上下文里，否则 runtime 镜像拷不到。
    assert!(
        DOCKERIGNORE.lines().any(|line| line.trim() == "web/dist"),
        "a local web/dist must stay out of the build context"
    );
    assert!(
        !DOCKERIGNORE
            .lines()
            .any(|line| line.trim().starts_with("container-web-dist")),
        "the CI-staged bundle must remain in the build context"
    );
}
