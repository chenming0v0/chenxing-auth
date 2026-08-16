//! `WEB_DIST_DIR` 的启动期解析：把「静态根是哪个目录」从请求期的环境变量读取，
//! 收敛成一个在启动时就 canonicalize 并逐条校验过的绝对路径（Issue #303）。
//!
//! 为什么必须放在启动期：
//!
//! - 请求期解析意味着配置错误只能以 404 表现，最坏的一种是把进程工作目录整体
//!   当静态根：`.env`、`data/keys` 下的私钥都会变成可下载文件。启动期拒绝把这类
//!   错误变成一条明确的配置错误，而不是一个安静的信息泄漏面。
//! - `ServeDir` 只做前缀拼接，不会替我们判断这个目录是不是前端构建产物根。
//!   「是可信产物根」必须自己证明：`index.html` 在盘上，且编译期内嵌的 SPA shell
//!   引用的每个根绝对资源都能在同一个根下找到——这正是 CI 暂存镜像产物时做的检查。
//! - `fs::canonicalize` 消掉 `..`、`.` 和符号链接，之后所有位置规则都对真实路径成立。
//!
//! 这里不提供任何「回退到工作目录」的分支：解析失败就是启动失败。

use std::{
    env, fs, io,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

/// 静态资源根目录的环境变量名。
pub const WEB_DIST_DIR_ENV: &str = "WEB_DIST_DIR";

/// 默认静态资源目录，相对于进程工作目录解析。
///
/// 仅在变量完全未设置时使用；空值是显式的配置错误，不会落到这里。
pub const DEFAULT_WEB_DIST_DIR: &str = "web/dist";

/// 编译期内嵌的 SPA shell，是本二进制唯一的 HTML 来源。
///
/// 磁盘上的同名文件不参与响应：内嵌副本与磁盘副本可能来自不同次构建，只保留一条
/// 路径才不会出现「shell 是新的、资源是旧的」这种半新半旧状态。磁盘副本的作用是
/// 证明产物根与本二进制同源——见 [`WebDistRoot::resolve`]。
pub const EMBEDDED_INDEX_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/web/dist/index.html"));

const INDEX_FILE: &str = "index.html";

/// 出现在候选根目录顶层即判定「这不是构建产物根」的条目。
///
/// Vite 产物里不会有源码、迁移、依赖或运行状态目录；它们出现说明这个路径指向了
/// 仓库根、部署目录或状态目录，把它当静态根等于把这些内容开放下载。
const SOURCE_OR_STATE_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "Cargo.lock",
    "src",
    "migrations",
    "node_modules",
    "target",
    "data",
    "keys",
];

/// 私钥与凭据材料的文件扩展名。命中即拒绝：产物根不允许与密钥存储重叠。
const SECRET_MATERIAL_EXTENSIONS: &[&str] =
    &["pem", "key", "der", "kid", "crt", "cer", "p12", "pfx"];

#[derive(Debug, Error)]
pub enum WebDistError {
    #[error(
        "WEB_DIST_DIR is set to an empty value; unset it to use the default relative bundle \
         path or point it at the built frontend bundle"
    )]
    Empty,
    #[error("cannot determine the process working directory: {0}")]
    WorkingDirectory(#[source] io::Error),
    #[error("WEB_DIST_DIR cannot be resolved: {}: {}", path.display(), source)]
    Unresolvable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("WEB_DIST_DIR is not a directory: {}", path.display())]
    NotADirectory { path: PathBuf },
    #[error("WEB_DIST_DIR resolves to a forbidden location: {}: {}", path.display(), reason)]
    ForbiddenLocation { path: PathBuf, reason: &'static str },
    #[error("WEB_DIST_DIR is not a frontend build artifact root: {}: {}", path.display(), reason)]
    NotABundle { path: PathBuf, reason: String },
}

/// 已校验的静态资源根：绝对、canonical，且证明过是本二进制对应的构建产物根。
///
/// 只能通过 [`WebDistRoot::resolve`] 构造，所以持有它就等于持有那份校验结论，
/// 请求路径上不需要再判断任何配置条件。
#[derive(Clone, Debug)]
pub struct WebDistRoot(PathBuf);

impl WebDistRoot {
    /// 按配置值与 `KEY_DIRECTORY` 解析静态资源根，工作目录取自当前进程。
    pub fn from_settings(configured: &str, key_directory: &str) -> Result<Self, WebDistError> {
        let working_directory = env::current_dir().map_err(WebDistError::WorkingDirectory)?;
        Self::resolve(configured, &working_directory, key_directory)
    }

    /// 解析并校验静态资源根。
    ///
    /// 工作目录与 `KEY_DIRECTORY` 作为参数传入而不是就地读取，这样位置规则可以在
    /// 不改动进程环境的前提下测试。校验顺序是「先位置、后内容」：位置不合法时不该
    /// 再去读目录内容，也不该在错误里暗示那个目录里有什么。
    pub fn resolve(
        configured: &str,
        working_directory: &Path,
        key_directory: &str,
    ) -> Result<Self, WebDistError> {
        let configured = configured.trim();
        if configured.is_empty() {
            return Err(WebDistError::Empty);
        }

        let requested = absolutize(Path::new(configured), working_directory);
        let root = match fs::canonicalize(&requested) {
            Ok(root) => root,
            Err(source) => {
                return Err(WebDistError::Unresolvable {
                    path: requested,
                    source,
                });
            }
        };
        if !root.is_dir() {
            return Err(WebDistError::NotADirectory { path: root });
        }

        check_location(&root, working_directory, key_directory)?;
        check_bundle(&root)?;
        Ok(Self(root))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// 位置规则：拒绝那些「即使目录里恰好有 index.html 也不能当静态根」的路径。
fn check_location(
    root: &Path,
    working_directory: &Path,
    key_directory: &str,
) -> Result<(), WebDistError> {
    let forbidden = |reason: &'static str| WebDistError::ForbiddenLocation {
        path: root.to_path_buf(),
        reason,
    };

    // 没有父目录只有文件系统根一种情况：它是所有秘密的祖先。
    if root.parent().is_none() {
        return Err(forbidden(
            "the filesystem root is never a build artifact directory",
        ));
    }

    // 等于或包含工作目录都拒绝：`.env` 与默认的 `data/keys` 都在工作目录之下，
    // 把它们纳入静态根就是把凭据开放下载。
    let working_directory = resolve_existing(working_directory);
    if working_directory.starts_with(root) {
        return Err(forbidden(
            "it is or contains the process working directory, which holds .env and runtime state",
        ));
    }

    // 与 KEY_DIRECTORY 的任何重叠关系都拒绝：相等、包含、被包含。
    let keys = resolve_existing(&absolutize(Path::new(key_directory), &working_directory));
    if overlaps(root, &keys) {
        return Err(forbidden(
            "it overlaps KEY_DIRECTORY, which holds signing keys and provider secrets",
        ));
    }

    Ok(())
}

/// 内容规则：证明这个目录是本二进制编译时那份构建产物根。
fn check_bundle(root: &Path) -> Result<(), WebDistError> {
    let not_a_bundle = |reason: String| WebDistError::NotABundle {
        path: root.to_path_buf(),
        reason,
    };

    // `ServeDir` serves nested paths too, so the bundle check must inspect the
    // same recursive namespace. Hidden entries, source maps and secret
    // material are never valid public assets at any depth.
    scan_bundle_entries(root, root, &not_a_bundle)?;

    if !root.join(INDEX_FILE).is_file() {
        return Err(not_a_bundle(format!("{INDEX_FILE} is missing")));
    }

    // 内嵌 shell 引用的资源就是这个二进制对静态根的全部要求，因此不硬编码
    // `assets/` 之类的布局：布局由产物自己声明，缺哪个文件就报哪个。
    let references = root_absolute_references(EMBEDDED_INDEX_HTML);
    if !references.iter().any(|reference| {
        bundle_relative_path(reference).is_some_and(|path| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("js"))
        })
    }) {
        return Err(not_a_bundle(
            "the embedded SPA shell references no script asset, so the bundle cannot be \
             verified; rebuild the frontend and the binary together"
                .to_owned(),
        ));
    }
    for reference in references {
        let Some(relative) = bundle_relative_path(reference) else {
            return Err(not_a_bundle(format!(
                "the embedded SPA shell references an unusable path ({reference})"
            )));
        };
        if !root.join(&relative).is_file() {
            return Err(not_a_bundle(format!(
                "the embedded SPA shell references {reference}, which is missing here; \
                 this directory is from a different build than this binary"
            )));
        }
    }

    Ok(())
}

/// 取出 HTML 里 `src="/..."` / `href="/..."` 形式的根绝对引用。
///
/// 只认根绝对路径：相对引用和外部 URL 不由静态根决定，无法也不必在这里校验。
fn root_absolute_references(html: &str) -> Vec<&str> {
    let mut references = Vec::new();
    for attribute in ["src=\"", "href=\""] {
        let mut rest = html;
        while let Some(start) = rest.find(attribute) {
            rest = &rest[start + attribute.len()..];
            let Some(end) = rest.find('"') else { break };
            let value = &rest[..end];
            rest = &rest[end + 1..];
            // `//host/path` 是协议相对 URL，不是本地路径。
            if value.starts_with('/') && !value.starts_with("//") {
                references.push(value);
            }
        }
    }
    references
}

/// 把根绝对引用换成产物根下的相对路径；无法安全落到根内时返回 `None`。
fn bundle_relative_path(reference: &str) -> Option<PathBuf> {
    let path = reference
        .split_once(['?', '#'])
        .map_or(reference, |(head, _)| head)
        .trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    let candidate = Path::new(path);
    // 引用来自内嵌 shell，本应是干净的相对路径；含 `..` 或根前缀时宁可报错，
    // 也不要用它去拼一个可能跑出产物根的路径。
    if candidate
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(candidate.to_path_buf())
}

fn is_secret_material(name: &str) -> bool {
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            SECRET_MATERIAL_EXTENSIONS
                .iter()
                .any(|secret| extension.eq_ignore_ascii_case(secret))
        })
}

/// Whether a request path is allowed to address a public bundle asset.
///
/// This is shared by startup validation and the request layer: a bundle can
/// change after startup, so `ServeDir` must apply the same fail-closed rules
/// to every path it is asked to serve.
pub(crate) fn is_public_asset_uri_path(path: &str) -> bool {
    let Some(relative) = path.strip_prefix('/') else {
        return false;
    };
    if relative.is_empty() || relative.contains('%') {
        return false;
    }
    is_public_asset_path(Path::new(relative))
}

pub(crate) fn is_public_asset_path(path: &Path) -> bool {
    path.components().all(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        !name.starts_with('.') && !is_source_map(name) && !is_secret_material(name)
    })
}

fn scan_bundle_entries(
    root: &Path,
    directory: &Path,
    not_a_bundle: &impl Fn(String) -> WebDistError,
) -> Result<(), WebDistError> {
    let entries = fs::read_dir(directory).map_err(|source| WebDistError::Unresolvable {
        path: directory.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| WebDistError::Unresolvable {
            path: directory.to_path_buf(),
            source,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(root)
            .unwrap_or(entry_path.as_path())
            .display()
            .to_string();

        let file_type = entry
            .file_type()
            .map_err(|source| WebDistError::Unresolvable {
                path: entry_path.clone(),
                source,
            })?;
        if file_type.is_symlink() {
            return Err(not_a_bundle(format!(
                "it holds a symbolic link ({relative})"
            )));
        }

        if !is_public_asset_path(
            entry_path
                .strip_prefix(root)
                .unwrap_or(entry_path.as_path()),
        ) {
            return Err(not_a_bundle(format!(
                "it holds a forbidden public asset ({relative})"
            )));
        }
        if SOURCE_OR_STATE_MARKERS.contains(&name.as_str()) && directory == root {
            return Err(not_a_bundle(format!(
                "it looks like a source or state directory ({name})"
            )));
        }

        if file_type.is_dir() {
            scan_bundle_entries(root, &entry_path, not_a_bundle)?;
        } else if !file_type.is_file() {
            return Err(not_a_bundle(format!(
                "it holds a non-regular public asset ({relative})"
            )));
        }
    }
    Ok(())
}

fn is_source_map(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("map"))
}

/// 相对路径按给定工作目录展开，并在词法层面消掉 `.` 与 `..`。
///
/// 词法归一化让「不存在的路径」也能参与位置比较：`KEY_DIRECTORY` 在首次启动时
/// 还没被创建，但它与产物根的祖先关系此刻就必须成立。
fn absolutize(path: &Path, working_directory: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_directory.join(path)
    };
    normalize(&joined)
}

fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// 能 canonicalize 就用真实路径，否则退回词法路径。
///
/// 位置规则要比较的是「同一个真实位置」，而符号链接会让两条字符串不同却指向同一处；
/// 但路径不存在时 canonicalize 必然失败，此时词法路径已经是能拿到的最好近似。
fn resolve_existing(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// 两条路径是否指向同一处，或其中一条包含另一条。
///
/// 按路径分量比较而不是字符串前缀：`/srv/app` 不是 `/srv/application` 的祖先。
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(test)]
#[path = "web_dist_tests.rs"]
mod tests;
