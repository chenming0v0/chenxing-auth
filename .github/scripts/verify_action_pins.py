#!/usr/bin/env python3
"""Reject mutable third-party GitHub Action references."""

from __future__ import annotations

import re
import sys
from os import walk
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
SKIPPED_DIRECTORIES = {".git", "node_modules", "target"}
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<value>.+?)\s*$")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
VERSION_COMMENT_RE = re.compile(
    r"^(?:v?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?|stable)(?:\s|$)"
)
PINNED_TOOLS = {"nextest", "cargo-audit", "cargo-llvm-cov"}
TOOL_RE = re.compile(r"^\s*tool:\s*(?P<value>[^#]+?)\s*(?:#.*)?$")
EXACT_TOOL_RE = re.compile(r"^(?P<name>[A-Za-z0-9_-]+)@\d+\.\d+\.\d+$")


def split_comment(value: str) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote == character:
                quote = None
            elif quote is None:
                quote = character
            continue
        if character == "#" and quote is None:
            return value[:index].strip(), value[index + 1 :].strip()
    return value.strip(), ""


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def github_action_files() -> list[Path]:
    files = {
        path
        for path in WORKFLOW_DIR.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    }
    for directory, subdirectories, filenames in walk(ROOT):
        subdirectories[:] = [
            name for name in subdirectories if name not in SKIPPED_DIRECTORIES
        ]
        for filename in filenames:
            if filename in {"action.yml", "action.yaml"}:
                files.add(Path(directory) / filename)
    return sorted(files)


def validate_file(path: Path) -> list[str]:
    errors: list[str] = []
    relative = path.relative_to(ROOT)
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        uses_match = USES_RE.match(line)
        if uses_match:
            raw_reference, comment = split_comment(uses_match.group("value"))
            reference = unquote(raw_reference)
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                errors.append(f"{relative}:{line_number}: external uses reference has no revision")
                continue
            revision = reference.rsplit("@", 1)[1]
            if not FULL_SHA_RE.fullmatch(revision):
                errors.append(
                    f"{relative}:{line_number}: external uses reference is not pinned to a full commit SHA"
                )
            if not VERSION_COMMENT_RE.match(comment):
                errors.append(
                    f"{relative}:{line_number}: pinned action needs a release/version comment"
                )

        tool_match = TOOL_RE.match(line)
        if not tool_match:
            continue
        for tool in re.split(r"[\s,]+", unquote(tool_match.group("value"))):
            if not tool:
                continue
            exact_match = EXACT_TOOL_RE.fullmatch(tool)
            tool_name = exact_match.group("name") if exact_match else tool.split("@", 1)[0]
            if tool_name in PINNED_TOOLS and exact_match is None:
                errors.append(
                    f"{relative}:{line_number}: {tool_name} must use an exact x.y.z version"
                )
    return errors


def main() -> int:
    errors = [error for path in github_action_files() for error in validate_file(path)]
    if errors:
        print("GitHub Actions supply-chain policy violations:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("GitHub Action references and release tools are immutably pinned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
