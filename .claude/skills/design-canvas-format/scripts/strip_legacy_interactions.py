#!/usr/bin/env python3
"""Remove legacy domId interactions from .design."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from design_common import LEGACY_DOM_IDS, default_design_path, interactions_for, load_design, save_design

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
    removed = 0
    for item in design.get("data", []):
        inter = interactions_for(item)
        new = [i for i in inter if i.get("domId") not in LEGACY_DOM_IDS]
        removed += len(inter) - len(new)
        item.setdefault("devMetadata", {})["interactions"] = new
    if args.dry_run:
        print(f"Would remove {removed}")
        return 0
    save_design(path, design)
    print(f"Removed {removed} legacy interaction(s)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
