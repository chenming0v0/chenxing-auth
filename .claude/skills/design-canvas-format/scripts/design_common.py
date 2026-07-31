#!/usr/bin/env python3
"""Shared helpers for chenmumu5-redesign-mobile .design tooling."""

from __future__ import annotations

import json
from pathlib import Path

LEGACY_DOM_IDS = frozenset({
    "open-code-regex", "open-code-script", "open-code-memory", "open-code-plugins",
    "open-code-regex-edit", "open-code-script-view-test", "open-code-regex-view-test",
    "open-code-script-open-test", "open-code-script-run-test", "open-script-manage-sheet",
})
REMOVED_PAGE_IDS = frozenset({"page-code-script-test", "page-splash", "page-chat-interface"})
# 已被新版接管的退役页：节点留在画布做对照，但不得再被任何 interactions 指向，自身出线必须为空
# （2026-07-26：chat-interface 收敛入 v2 后节点已彻底删除，转入 REMOVED_PAGE_IDS）
RETIRED_PAGE_IDS = frozenset()

def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[4]

def default_project_dir(root: Path | None = None) -> Path:
    return (root or repo_root_from_script()) / "chenmumu5-redesign-mobile"

def default_design_path(project_dir: Path | None = None) -> Path:
    return (project_dir or default_project_dir()) / "chenmumu5-redesign-mobile.design"

def load_design(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def save_design(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def page_items(design: dict) -> list:
    return [item for item in design.get("data", []) if item.get("type") == "page"]

def page_ids(design: dict) -> set:
    return {item["id"] for item in page_items(design) if item.get("id")}

def interactions_for(page: dict) -> list:
    return page.get("devMetadata", {}).get("interactions", []) or []
