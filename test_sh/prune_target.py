#!/usr/bin/env python3
"""辰星认证中枢 - Cargo 产物剪枝器。

## 为什么需要它

`target/<profile>/deps/` 里的文件名是 `名字-<hash>`，hash 由 feature 组合、
profile、依赖版本、rustc 版本共同决定。只要其中任何一项变化，Cargo 就生成
一个新 hash 的产物，**旧的不会被删除**。本项目有 6 个集成测试目标，每个带完整
调试信息约 242 MiB，因此每换一套编译配置仍会增加约 1.5 GiB。历史上的多目标
布局叠加多套编译配置，曾让 target 涨到 160 GiB。

## 判定「活着」的两种模式

- `exact`：由调用方提供 `--live-file`（来自 `cargo test --no-run
  --message-format json-render-diagnostics` 的 artifact 路径）。这是 Cargo
  自己报告的产物清单，不在清单里的可执行文件一定是陈旧配置的残留。
  只有在**完整**编译（不限定 target）后才允许使用，否则会误删未参与本次
  编译的合法测试二进制。
- `heuristic`：不编译，按 `名字-<hash>` 分组，每组只保留 mtime 最新的一份。
  同一目标在同一 profile 下只有一份是活的，因此去重永远安全。

## 安全边界

- 只处理 `target/<profile>/deps/`（以及 `--deep` 下的 `incremental/`）。
  `.fingerprint/`、`build/`、profile 根目录一律不碰。
- 删除前收集 profile 根目录所有文件的 inode。Cargo 把最终产物硬链接到
  profile 根目录（如 `target/debug/chenxing-auth`），同 inode 的 deps 条目
  受保护，避免删掉正在使用的主二进制。
- 默认只删可执行文件；`.rlib` / `.rmeta` / `.so` 需要 `--deep`，因为删它们
  会让下一次 `cargo check` 重新编译整棵依赖树。
- 目标目录必须位于仓库内（`--repo-root`），且必须长得像 Cargo target 目录。
- 不跟随符号链接。`--dry-run` 只报告不删除。

最坏情况只是下次编译变慢，不会破坏源码或 Cargo 状态。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

# 库产物：删掉会触发依赖树重编译，只在 --deep 下考虑。
LIB_SUFFIXES = {".rlib", ".rmeta", ".so", ".dylib", ".dll", ".a", ".lib", ".wasm"}
# 附属产物：依附于某个主产物，主产物没了就是孤儿。
AUX_SUFFIXES = {".d"}
# Cargo 的 metadata hash 后缀，长度随版本浮动，放宽到 8-17。
HASH_SUFFIX = re.compile(r"^(?P<group>.+)-[0-9a-f]{8,17}$")

GIB = 1024**3


def human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def group_of(name: str) -> str:
    """去掉 Cargo 的 hash 后缀，得到逻辑目标名。"""
    matched = HASH_SUFFIX.match(name)
    return matched.group("group") if matched else name


def load_live_paths(live_file: Path) -> set[Path]:
    """读取 Cargo JSON 输出，收集本次编译真正使用的产物路径。"""
    live: set[Path] = set()
    with live_file.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("reason") != "compiler-artifact":
                continue
            for path in message.get("filenames") or []:
                live.add(Path(path).resolve())
            executable = message.get("executable")
            if executable:
                live.add(Path(executable).resolve())
    return live


def protected_inodes(profile_dir: Path) -> set[tuple[int, int]]:
    """profile 根目录里的文件是 Cargo 硬链接出来的最终产物，按 inode 保护。"""
    inodes: set[tuple[int, int]] = set()
    try:
        entries = list(os.scandir(profile_dir))
    except OSError:
        return inodes
    for entry in entries:
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        inodes.add((info.st_dev, info.st_ino))
    return inodes


def directory_size(root: Path) -> int:
    """去重 inode 的目录占用，避免硬链接被重复计算。"""
    seen: set[tuple[int, int]] = set()
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            key = (info.st_dev, info.st_ino)
            if key in seen:
                continue
            seen.add(key)
            total += info.st_size
    return total


class Entry:
    """deps/ 下的一个候选条目。"""

    __slots__ = ("path", "size", "mtime", "key", "is_dir", "kind", "group")

    def __init__(self, path: Path, kind: str, size: int, mtime: float, key, is_dir: bool):
        self.path = path
        self.kind = kind
        self.size = size
        self.mtime = mtime
        self.key = key
        self.is_dir = is_dir
        self.group = group_of(path.name.split(".")[0] if is_dir else path.stem if path.suffix else path.name)


def scan_deps(deps_dir: Path) -> tuple[list[Entry], list[Entry], dict[str, list[Path]]]:
    """把 deps/ 分成可执行产物、库产物、附属产物三类。"""
    executables: list[Entry] = []
    libraries: list[Entry] = []
    auxiliaries: dict[str, list[Path]] = {}

    for entry in os.scandir(deps_dir):
        path = Path(entry.path)
        if entry.is_symlink():
            continue

        if entry.is_dir(follow_symlinks=False):
            # macOS 的调试符号目录依附于同名可执行文件。
            if path.name.endswith(".dSYM"):
                stem = path.name[: -len(".dSYM")]
                auxiliaries.setdefault(stem, []).append(path)
            continue

        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue

        suffix = path.suffix
        if suffix in AUX_SUFFIXES:
            auxiliaries.setdefault(path.stem, []).append(path)
            continue

        item = Entry(path, "", info.st_size, info.st_mtime, (info.st_dev, info.st_ino), False)
        if suffix in LIB_SUFFIXES:
            item.kind = "lib"
            libraries.append(item)
        elif info.st_mode & 0o111 and suffix in ("", ".exe"):
            item.kind = "exe"
            executables.append(item)
        # 其余（.o、.json 等）不属于本工具职责，跳过。

    return executables, libraries, auxiliaries


def newest_per_group(items: list[Entry], window: float) -> set[Path]:
    """保留每个逻辑目标最近一次构建产出的全部产物。

    同一组名下可以同时存在多个**活的**产物：例如 `chenxing_auth-<hash>` 既是
    lib 测试壳，也是 bin 测试壳，Cargo 用不同 hash 区分。只留 mtime 最新的一份
    会误删另一份。因此保留窗口内（默认同一次构建的 120 秒）的所有产物，
    只删更早配置的残留。
    """
    latest: dict[str, float] = {}
    for item in items:
        if item.mtime > latest.get(item.group, 0.0):
            latest[item.group] = item.mtime
    return {item.path for item in items if item.mtime >= latest[item.group] - window}


def select_removals(
    executables: list[Entry],
    libraries: list[Entry],
    mode: str,
    deep: bool,
    live: set[Path],
    protected: set[tuple[int, int]],
    window: float,
) -> list[Entry]:
    """决定删哪些。保留集合永远优先于删除集合。"""
    keep_newest_exe = newest_per_group(executables, window) if mode == "heuristic" else set()
    keep_newest_lib = newest_per_group(libraries, window) if mode == "heuristic" else set()

    removals: list[Entry] = []

    for item in executables:
        if item.key in protected:
            continue
        if mode == "exact":
            if item.path.resolve() in live:
                continue
        elif item.path in keep_newest_exe:
            continue
        removals.append(item)

    if deep:
        for item in libraries:
            if item.key in protected:
                continue
            if mode == "exact":
                if item.path.resolve() in live:
                    continue
            elif item.path in keep_newest_lib:
                continue
            removals.append(item)

    return removals


def remove_path(path: Path, dry_run: bool) -> int:
    """删除文件或目录，返回释放的字节数。"""
    try:
        if path.is_dir() and not path.is_symlink():
            freed = directory_size(path)
            if not dry_run:
                shutil.rmtree(path, ignore_errors=True)
            return freed
        freed = path.lstat().st_size
        if not dry_run:
            path.unlink()
        return freed
    except OSError as error:
        print(f"  跳过 {path.name}：{error}", file=sys.stderr)
        return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="prune_target.py",
        description="删除 Cargo target 目录里陈旧的测试二进制，释放磁盘",
    )
    parser.add_argument("--target-dir", default="target", help="Cargo target 目录（默认 target）")
    parser.add_argument("--profile", default="debug", help="profile 子目录（默认 debug）")
    parser.add_argument(
        "--mode",
        choices=("exact", "heuristic"),
        default="heuristic",
        help="exact 需要 --live-file，仅可用于完整编译之后；heuristic 只做同名去重",
    )
    parser.add_argument("--live-file", type=Path, help="cargo JSON 输出文件，用于 exact 模式")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="额外清理 incremental 缓存与陈旧 rlib/rmeta（下次编译会变慢）",
    )
    parser.add_argument(
        "--keep-window",
        type=float,
        default=120.0,
        help="heuristic 模式下，同组内距最新产物多少秒内的都算同一次构建（默认 120）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只报告不删除")
    parser.add_argument("--verbose", action="store_true", help="逐条打印删除项")
    parser.add_argument("--repo-root", default=".", help="安全边界：target 必须在此目录内")
    parser.add_argument("--allow-outside", action="store_true", help="允许 target 位于仓库之外")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    target_dir = Path(args.target_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    profile_dir = target_dir / args.profile
    deps_dir = profile_dir / "deps"

    if not args.allow_outside and repo_root not in target_dir.parents and target_dir != repo_root:
        print(f"拒绝操作仓库之外的目录：{target_dir}", file=sys.stderr)
        return 2
    if not (target_dir / "CACHEDIR.TAG").exists() and not deps_dir.is_dir():
        print(f"{target_dir} 不像 Cargo target 目录，已中止", file=sys.stderr)
        return 2
    if not deps_dir.is_dir():
        print(f"RESULT deleted=0 freed=0 target={directory_size(target_dir)}")
        return 0

    live: set[Path] = set()
    if args.mode == "exact":
        if not args.live_file or not args.live_file.is_file():
            print("exact 模式需要有效的 --live-file", file=sys.stderr)
            return 2
        live = load_live_paths(args.live_file)
        live_executables = sum(1 for path in live if path.parent == deps_dir and not path.suffix)
        # 清单异常小意味着编译范围被限定过，此时全量剪枝会误删合法二进制。
        if live_executables < 2:
            print(
                f"live 清单只有 {live_executables} 个可执行产物，疑似受限编译，"
                "已回退到 heuristic 模式",
                file=sys.stderr,
            )
            args.mode = "heuristic"

    protected = protected_inodes(profile_dir)
    executables, libraries, auxiliaries = scan_deps(deps_dir)
    removals = select_removals(
        executables, libraries, args.mode, args.deep, live, protected, args.keep_window
    )

    removal_paths = {item.path for item in removals}
    removed_stems = {item.path.stem if item.path.suffix else item.path.name for item in removals}
    kept_stems = {
        (item.path.stem if item.path.suffix else item.path.name)
        for item in executables + libraries
        if item.path not in removal_paths
    }

    deleted = 0
    freed = 0

    for item in removals:
        if args.verbose:
            print(f"  删除 {item.path.name}（{human(item.size)}）")
        gained = remove_path(item.path, args.dry_run)
        if gained or args.dry_run:
            deleted += 1
            freed += gained

    # 附属产物：主产物已被删除且没有同名活产物时才算孤儿。
    for stem, paths in auxiliaries.items():
        if stem in kept_stems or stem not in removed_stems:
            continue
        for path in paths:
            gained = remove_path(path, args.dry_run)
            deleted += 1
            freed += gained

    if args.deep:
        incremental = profile_dir / "incremental"
        if incremental.is_dir():
            gained = remove_path(incremental, args.dry_run)
            if gained:
                deleted += 1
                freed += gained
                if args.verbose:
                    print(f"  删除 incremental 缓存（{human(gained)}）")

    print(f"RESULT deleted={deleted} freed={freed} target={directory_size(target_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
