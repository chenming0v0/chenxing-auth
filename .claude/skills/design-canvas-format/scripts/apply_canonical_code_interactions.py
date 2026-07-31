#!/usr/bin/env python3
"""Overwrite page-code-* interactions with canonical lists (see interactions.md)."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from design_common import default_design_path, load_design, save_design

NAV = [
    {"domId": "nav-chat", "targetPageId": "page-chat-list"},
    {"domId": "nav-characters", "targetPageId": "page-character-list"},
    {"domId": "nav-presets", "targetPageId": "page-preset-manager"},
    {"domId": "nav-world", "targetPageId": "page-world-book"},
]
L2 = [
    {"domId": "open-code-tab-regex", "targetPageId": "page-code-manager"},
    {"domId": "open-code-tab-script", "targetPageId": "page-code-script-library"},
    {"domId": "open-code-tab-memory", "targetPageId": "page-code-memory-presets"},
    {"domId": "open-code-tab-plugins", "targetPageId": "page-code-plugins"},
]
REGEX_L3 = [
    {"domId": "open-code-regex-view-list", "targetPageId": "page-code-manager"},
    {"domId": "open-code-regex-view-edit", "targetPageId": "page-code-regex-test"},
    {"domId": "open-code-regex-open-item", "targetPageId": "page-code-regex-test"},
]
SCRIPT_L3 = [
    {"domId": "open-code-script-view-library", "targetPageId": "page-code-script-library"},
    {"domId": "open-code-script-view-edit", "targetPageId": "page-code-script-editor"},
]
SCRIPT_ACTIONS = [
    {"domId": "open-code-script-create", "targetPageId": "page-code-script-editor"},
    {"domId": "open-code-script-create-folder", "targetPageId": "page-code-script-editor"},
    {"domId": "open-code-script-open-edit", "targetPageId": "page-code-script-editor"},
    {"domId": "open-code-script-open-edit-secondary", "targetPageId": "page-code-script-editor"},
    {"domId": "open-code-script-folder-edit", "targetPageId": "page-code-script-editor"},
    {"domId": "open-code-script-import", "targetPageId": "page-code-script-library"},
]
MEMORY_L3 = [
    {"domId": "open-code-memory-view-presets", "targetPageId": "page-code-memory-presets"},
    {"domId": "open-code-memory-view-prompts", "targetPageId": "page-code-memory-prompts"},
    {"domId": "open-code-memory-view-table", "targetPageId": "page-code-memory-table"},
    {"domId": "open-code-memory-view-global", "targetPageId": "page-code-memory-global"},
]

def base(extra=None):
    out = NAV + L2
    return (extra or []) + out

MEMORY_BACK = [{"domId": "back-to-code-manager", "targetPageId": "page-code-manager"}]

CANON = {
    "page-code-manager": base(REGEX_L3),
    "page-code-regex-test": base(MEMORY_BACK + REGEX_L3),
    "page-code-script-library": base(MEMORY_BACK + SCRIPT_L3 + SCRIPT_ACTIONS),
    "page-code-script-editor": base(MEMORY_BACK + SCRIPT_L3 + SCRIPT_ACTIONS),
    "page-code-memory-presets": base(
        MEMORY_BACK
        + MEMORY_L3
        + [{"domId": "open-code-memory-open-prompts", "targetPageId": "page-code-memory-prompts"}]
    ),
    "page-code-memory-prompts": base(MEMORY_BACK + MEMORY_L3),
    "page-code-memory-table": base(MEMORY_BACK + MEMORY_L3),
    "page-code-memory-global": base(MEMORY_BACK + MEMORY_L3),
    "page-code-plugins": base([{"domId": "open-settings", "targetPageId": "page-settings-sidebar"}]),
}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    path = default_design_path() if not args.design else Path(args.design)
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 1
    design = load_design(path)
    n = 0
    for item in design.get("data", []):
        if item.get("id") in CANON:
            item.setdefault("devMetadata", {})["interactions"] = CANON[item["id"]]
            n += 1
    if args.dry_run:
        print(f"Would update {n} page(s)")
        return 0
    save_design(path, design)
    print(f"Updated {n} page(s) in {path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
