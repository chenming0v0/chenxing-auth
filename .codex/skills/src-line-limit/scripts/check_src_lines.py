#!/usr/bin/env python3
"""Check physical line limits for Git-visible files under src paths."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys


WARNING_LIMIT = 300
ERROR_LIMIT = 500


class CheckError(Exception):
    """An invocation or repository error that should exit with status 2."""


def run_git(cwd: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise CheckError(f"could not run git: {error}") from error

    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        command = "git " + " ".join(args)
        raise CheckError(f"{command} failed: {detail or 'unknown Git error'}")
    return result.stdout


def resolve_repo_root(root_arg: str | None) -> Path:
    candidate = Path(root_arg).expanduser() if root_arg else Path.cwd()
    if not candidate.is_dir():
        raise CheckError(f"repository path is not a directory: {candidate}")

    output = run_git(candidate, "rev-parse", "--show-toplevel")
    root_text = output.decode("utf-8", errors="strict").strip()
    if not root_text:
        raise CheckError("git returned an empty repository root")
    root = Path(root_text).resolve()
    if not root.is_dir():
        raise CheckError(f"Git repository root is not a directory: {root}")
    return root


def decode_git_paths(output: bytes) -> set[str]:
    return {os.fsdecode(path) for path in output.split(b"\0") if path}


def collect_paths(root: Path, check_all: bool, base: str | None) -> list[str]:
    if check_all:
        paths = decode_git_paths(
            run_git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
        )
    else:
        paths = decode_git_paths(
            run_git(
                root,
                "diff",
                "--name-only",
                "--diff-filter=ACMRTUXB",
                "-z",
                "HEAD",
                "--",
            )
        )
        paths.update(
            decode_git_paths(run_git(root, "ls-files", "--others", "--exclude-standard", "-z"))
        )
        if base:
            paths.update(
                decode_git_paths(
                    run_git(
                        root,
                        "diff",
                        "--name-only",
                        "--diff-filter=ACMRTUXB",
                        "-z",
                        f"{base}...HEAD",
                        "--",
                    )
                )
            )
    return sorted(paths)


def is_src_path(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    return not path.is_absolute() and ".." not in path.parts and "src" in path.parts


def count_text_lines(path: Path) -> int | None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CheckError(f"could not inspect {path}: {error}") from error

    if not stat.S_ISREG(mode):
        return None

    try:
        content = path.read_bytes()
    except OSError as error:
        raise CheckError(f"could not read {path}: {error}") from error

    if b"\0" in content:
        return None
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if not content:
        return 0
    return content.count(b"\n") + (not content.endswith(b"\n"))


def check_files(root: Path, paths: list[str]) -> int:
    checked = 0
    skipped = 0
    warnings = 0
    errors = 0

    for relative_path in paths:
        if not is_src_path(relative_path):
            continue
        line_count = count_text_lines(root / relative_path)
        if line_count is None:
            skipped += 1
            continue

        checked += 1
        if line_count > ERROR_LIMIT:
            print(f"ERROR {relative_path}: {line_count} lines (limit {ERROR_LIMIT})")
            errors += 1
        elif line_count > WARNING_LIMIT:
            print(f"WARNING {relative_path}: {line_count} lines (limit {WARNING_LIMIT})")
            warnings += 1

    skipped_suffix = f"; skipped {skipped} non-text or non-regular file(s)" if skipped else ""
    if checked == 0:
        print(f"OK: no matching UTF-8 text files under a src path{skipped_suffix}")
    elif warnings == 0 and errors == 0:
        print(f"OK: checked {checked} src file(s); no files exceed {WARNING_LIMIT} lines{skipped_suffix}")
    else:
        print(
            f"SUMMARY: checked {checked} src file(s); "
            f"{warnings} warning(s), {errors} error(s){skipped_suffix}"
        )
    return 1 if errors else 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--all", action="store_true", help="check tracked and untracked non-ignored files")
    scope.add_argument("--base", metavar="REF", help="also include committed changes from REF to HEAD")
    parser.add_argument("--root", metavar="PATH", help="Git worktree or a directory inside it")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        root = resolve_repo_root(args.root)
        paths = collect_paths(root, args.all, args.base)
        return check_files(root, paths)
    except (CheckError, UnicodeDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
