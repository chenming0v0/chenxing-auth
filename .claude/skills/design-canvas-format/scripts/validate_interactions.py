#!/usr/bin/env python3
"""Validate .design interactions against project conventions."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from design_common import (
    LEGACY_DOM_IDS, REMOVED_PAGE_IDS, RETIRED_PAGE_IDS, default_design_path,
    interactions_for, load_design, page_ids, page_items,
)
CODE_L2_EXPECTED = {
    "open-code-tab-regex": "page-code-manager",
    "open-code-tab-script": "page-code-script-library",
    "open-code-tab-memory": "page-code-memory-presets",
    "open-code-tab-plugins": "page-code-plugins",
}

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate .design interactions")
    parser.add_argument("--design", default="")
    args = parser.parse_args()
    path = default_design_path() if not args.design else Path(args.design)
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 1
    design = load_design(path)
    ids = page_ids(design)
    errors, warnings = [], []
    for item in page_items(design):
        pid = item.get("id", "")
        for inter in interactions_for(item):
            dom, target = inter.get("domId", ""), inter.get("targetPageId", "")
            if target not in ids:
                errors.append(f"{pid}: missing target `{target}` from `{dom}`")
            if dom in LEGACY_DOM_IDS:
                errors.append(f"{pid}: legacy domId `{dom}`")
            if target in REMOVED_PAGE_IDS:
                errors.append(f"{pid}: removed page `{target}` via `{dom}`")
            if dom == "open-script-manage-sheet":
                warnings.append(f"{pid}: drawer-only `{dom}` should not be wired")
            if dom in CODE_L2_EXPECTED and target != CODE_L2_EXPECTED[dom]:
                errors.append(f"{pid}: `{dom}` -> `{CODE_L2_EXPECTED[dom]}`, got `{target}`")
            if target in RETIRED_PAGE_IDS:
                errors.append(f"{pid}: retired page `{target}` via `{dom}` (superseded, redirect to its v2)")
        if pid in RETIRED_PAGE_IDS and interactions_for(item):
            errors.append(f"{pid}: retired page must keep interactions empty")
    if warnings:
        print("Warnings:")
        for w in warnings: print(f"  - {w}")
    if errors:
        print("Errors:")
        for e in errors: print(f"  - {e}")
        return 2
    print("OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
