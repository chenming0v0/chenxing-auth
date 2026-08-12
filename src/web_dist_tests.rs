//! `web_dist.rs` 的单元测试。
//!
//! 产物根用临时目录按内嵌 shell 的引用列表现搭，因此断言与具体的内容哈希无关，
//! 前端每次重建都不会让这些用例失效。

use super::*;

/// 测试临时目录的 RAII 清理卫士。
struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let path = env::temp_dir().join(format!("chenxing-web-dist-{name}-{unique}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(fs::canonicalize(&path).expect("canonical temporary directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn child(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 按内嵌 shell 的引用列表在 `root` 下搭出一份最小可信产物。
fn write_bundle(root: &Path) {
    fs::create_dir_all(root).expect("bundle root");
    fs::write(root.join("index.html"), EMBEDDED_INDEX_HTML).expect("index.html");
    for reference in root_absolute_references(EMBEDDED_INDEX_HTML) {
        let relative = bundle_relative_path(reference).expect("embedded reference is usable");
        let target = root.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("asset directory");
        }
        fs::write(&target, b"asset").expect("asset file");
    }
}

/// 与产物根无重叠的密钥目录：位置规则的默认参数。
fn unrelated_key_directory(guard: &TempDirGuard) -> String {
    guard.child("keys-elsewhere").to_string_lossy().into_owned()
}

#[test]
fn resolve_accepts_a_bundle_root_and_returns_a_canonical_path() {
    let guard = TempDirGuard::new("accept");
    let root = guard.child("dist");
    write_bundle(&root);

    let resolved = WebDistRoot::resolve(
        &root.to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect("a real bundle root must be accepted");

    assert_eq!(resolved.path(), root.as_path());
    assert!(resolved.path().is_absolute());
}

/// 相对配置值按工作目录展开，且 `..` / `.` 在校验前就被消掉。
#[test]
fn resolve_absolutizes_relative_values_against_the_working_directory() {
    let guard = TempDirGuard::new("relative");
    let root = guard.child("nested/dist");
    write_bundle(&root);

    let resolved = WebDistRoot::resolve(
        "nested/../nested/./dist",
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect("relative bundle path must resolve against the working directory");

    assert_eq!(resolved.path(), root.as_path());
}

/// 空值是配置错误，不允许回退到默认值或工作目录。
#[test]
fn empty_values_are_rejected_without_any_fallback() {
    let guard = TempDirGuard::new("empty");
    let keys = unrelated_key_directory(&guard);

    for value in ["", "   ", "\t\n"] {
        let error = WebDistRoot::resolve(value, guard.path(), &keys)
            .expect_err("an empty WEB_DIST_DIR must fail closed");
        assert!(matches!(error, WebDistError::Empty), "{value:?}: {error}");
    }
}

#[test]
fn missing_directories_fail_at_startup_instead_of_at_request_time() {
    let guard = TempDirGuard::new("missing");
    let error = WebDistRoot::resolve(
        &guard.child("absent").to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect_err("a missing bundle directory must fail closed");

    assert!(
        matches!(error, WebDistError::Unresolvable { .. }),
        "{error}"
    );
}

#[test]
fn a_file_is_not_a_static_root() {
    let guard = TempDirGuard::new("file");
    let file = guard.child("dist");
    fs::write(&file, b"not a directory").expect("regular file");

    let error = WebDistRoot::resolve(
        &file.to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect_err("a regular file must be rejected");

    assert!(
        matches!(error, WebDistError::NotADirectory { .. }),
        "{error}"
    );
}

/// 文件系统根是所有秘密的祖先，任何时候都不是产物根。
#[test]
fn the_filesystem_root_is_rejected() {
    let guard = TempDirGuard::new("fsroot");
    let error = WebDistRoot::resolve("/", guard.path(), &unrelated_key_directory(&guard))
        .expect_err("the filesystem root must be rejected");

    assert!(
        matches!(error, WebDistError::ForbiddenLocation { .. }),
        "{error}"
    );
}

/// 工作目录本身持有 `.env` 与运行状态，等于或包含它都必须拒绝。
#[test]
fn the_working_directory_and_its_ancestors_are_rejected() {
    let guard = TempDirGuard::new("cwd");
    let working_directory = guard.child("run");
    fs::create_dir_all(&working_directory).expect("working directory");
    let keys = unrelated_key_directory(&guard);

    for candidate in [working_directory.clone(), guard.path().to_path_buf()] {
        let error = WebDistRoot::resolve(&candidate.to_string_lossy(), &working_directory, &keys)
            .expect_err("the working directory must never become the static root");
        assert!(
            matches!(error, WebDistError::ForbiddenLocation { .. }),
            "{}: {error}",
            candidate.display()
        );
    }
}

/// 与 `KEY_DIRECTORY` 的任何重叠关系都拒绝：相等、包含、被包含。
#[test]
fn any_overlap_with_the_key_directory_is_rejected() {
    let guard = TempDirGuard::new("keys");
    let keys = guard.child("state/keys");
    fs::create_dir_all(&keys).expect("key directory");
    let keys_value = keys.to_string_lossy().into_owned();

    let inside_keys = keys.join("dist");
    write_bundle(&inside_keys);

    for candidate in [keys.clone(), guard.child("state"), inside_keys] {
        let error = WebDistRoot::resolve(&candidate.to_string_lossy(), guard.path(), &keys_value)
            .expect_err("KEY_DIRECTORY overlap must be rejected");
        assert!(
            matches!(error, WebDistError::ForbiddenLocation { .. }),
            "{}: {error}",
            candidate.display()
        );
    }
}

/// 相对的 `KEY_DIRECTORY`（默认 `data/keys`）同样按工作目录展开后参与比较。
#[test]
fn relative_key_directories_still_overlap_check() {
    let guard = TempDirGuard::new("relkeys");
    let root = guard.child("data/keys");
    write_bundle(&root);

    let error = WebDistRoot::resolve(&root.to_string_lossy(), guard.path(), "data/keys")
        .expect_err("a relative KEY_DIRECTORY must resolve before the overlap check");

    assert!(
        matches!(error, WebDistError::ForbiddenLocation { .. }),
        "{error}"
    );
}

/// 仓库根、部署目录这类路径由顶层标记条目识别，而不是靠某个开发期路径。
#[test]
fn source_and_state_markers_reject_repository_like_roots() {
    for marker in ["Cargo.toml", "src", "migrations", ".git", "data", "target"] {
        let guard = TempDirGuard::new("marker");
        let root = guard.child("dist");
        write_bundle(&root);
        let marked = root.join(marker);
        if marker.contains('.') {
            fs::write(&marked, b"marker").expect("marker file");
        } else {
            fs::create_dir_all(&marked).expect("marker directory");
        }

        let error = WebDistRoot::resolve(
            &root.to_string_lossy(),
            guard.path(),
            &unrelated_key_directory(&guard),
        )
        .expect_err("a source or state directory must not be served");

        assert!(
            matches!(error, WebDistError::NotABundle { .. }),
            "{marker}: {error}"
        );
    }
}

/// 私钥、`.env` 之类的材料出现在候选根顶层时拒绝：产物根不与秘密存储共处。
#[test]
fn secret_material_in_the_root_is_rejected() {
    for name in [".env", ".env.production", "active-rs256.kid", "tls.pem"] {
        let guard = TempDirGuard::new("secret");
        let root = guard.child("dist");
        write_bundle(&root);
        fs::write(root.join(name), b"secret").expect("secret material");

        let error = WebDistRoot::resolve(
            &root.to_string_lossy(),
            guard.path(),
            &unrelated_key_directory(&guard),
        )
        .expect_err("secret material must not be served");

        assert!(
            matches!(error, WebDistError::NotABundle { .. }),
            "{name}: {error}"
        );
    }
}

#[test]
fn a_directory_without_index_html_is_not_a_bundle() {
    let guard = TempDirGuard::new("noindex");
    let root = guard.child("dist");
    write_bundle(&root);
    fs::remove_file(root.join("index.html")).expect("remove index.html");

    let error = WebDistRoot::resolve(
        &root.to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect_err("a directory without index.html must be rejected");

    assert!(matches!(error, WebDistError::NotABundle { .. }), "{error}");
}

/// 只放一个 `index.html` 不足以充当产物根：内嵌 shell 引用的资源必须都在。
#[test]
fn a_bundle_missing_the_referenced_assets_is_rejected() {
    let guard = TempDirGuard::new("noassets");
    let root = guard.child("dist");
    fs::create_dir_all(&root).expect("bundle root");
    fs::write(root.join("index.html"), EMBEDDED_INDEX_HTML).expect("index.html");

    let error = WebDistRoot::resolve(
        &root.to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect_err("a bundle without the referenced assets must be rejected");

    assert!(matches!(error, WebDistError::NotABundle { .. }), "{error}");
}

/// 换成另一次构建的产物（哈希文件名不同）必须拒绝，否则每个资源都会 404。
#[test]
fn a_bundle_from_another_build_is_rejected() {
    let guard = TempDirGuard::new("foreign");
    let root = guard.child("dist");
    write_bundle(&root);

    // 模拟「另一次构建」：内容哈希不同，于是文件名不同。
    let script = root_absolute_references(EMBEDDED_INDEX_HTML)
        .into_iter()
        .filter_map(bundle_relative_path)
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("js"))
        })
        .expect("the embedded shell references a script asset");
    let script = root.join(script);
    let renamed = script.with_file_name(format!(
        "foreign-{}",
        script.file_name().expect("asset name").to_string_lossy()
    ));
    fs::rename(&script, &renamed).expect("rename asset");

    let error = WebDistRoot::resolve(
        &root.to_string_lossy(),
        guard.path(),
        &unrelated_key_directory(&guard),
    )
    .expect_err("a bundle from a different build must be rejected");

    assert!(matches!(error, WebDistError::NotABundle { .. }), "{error}");
}

/// 内嵌 shell 必须自带一个带哈希的脚本引用，否则「同源产物」这条校验无从成立。
#[test]
fn the_embedded_shell_references_a_hashed_script() {
    let references = root_absolute_references(EMBEDDED_INDEX_HTML);
    assert!(
        references
            .iter()
            .any(|reference| reference.ends_with(".js")),
        "the embedded shell must reference a script asset: {references:?}"
    );
}

#[test]
fn bundle_relative_paths_reject_traversal_and_empty_references() {
    assert_eq!(
        bundle_relative_path("/assets/index-abc.js"),
        Some(PathBuf::from("assets/index-abc.js"))
    );
    // 查询串与 fragment 不属于文件名
    assert_eq!(
        bundle_relative_path("/favicon.png?v=2"),
        Some(PathBuf::from("favicon.png"))
    );
    assert_eq!(bundle_relative_path("/"), None);
    assert_eq!(bundle_relative_path("/../../etc/passwd"), None);
}

#[test]
fn root_absolute_references_ignores_external_and_relative_urls() {
    let html = r#"<link href="https://cdn.example.com/a.css"><link href="//cdn/b.css">
        <script src="./local.js"></script><script src="/assets/app.js"></script>"#;

    assert_eq!(root_absolute_references(html), vec!["/assets/app.js"]);
}

#[test]
fn overlap_compares_by_path_components_not_string_prefixes() {
    let base = Path::new("/srv/app");
    assert!(overlaps(base, base));
    assert!(overlaps(base, Path::new("/srv/app/dist")));
    assert!(overlaps(Path::new("/srv/app/dist"), base));
    // 字符串前缀相同但两者互不包含
    assert!(!overlaps(base, Path::new("/srv/application")));
    assert!(!overlaps(base, Path::new("/srv/other")));
}
