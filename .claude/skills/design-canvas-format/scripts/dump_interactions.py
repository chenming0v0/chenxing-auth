#!/usr/bin/env python3
"""Print all page interactions from a .design file."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from design_common import default_design_path, interactions_for, load_design, page_items

def main() -> int:
    parser = argparse.ArgumentParser(description="Dump interactions from .design JSON")
    parser.add_argument("--design", default="")
    parser.add_argument("--page", default="", help="Filter page id prefix")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    path = default_design_path() if not args.design else Path(args.design)
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 1
    design = load_design(path)
    rows = []
    for item in sorted(page_items(design), key=lambda x: x.get("id", "")):
        pid = item.get("id", "")
        if args.page and not pid.startswith(args.page):
            continue
        title = item.get("title", "")
        for inter in sorted(interactions_for(item), key=lambda x: x.get("domId", "")):
            rows.append((pid, title, inter.get("domId", ""), inter.get("targetPageId", "")))
    if args.markdown:
        print("| page id | title | domId | targetPageId |")
        print("|---------|-------|-------|--------------|")
        for pid, title, dom, target in rows:
            print(f"| `{pid}` | {title} | `{dom}` | `{target}` |")
    else:
        current = None
        for pid, title, dom, target in rows:
            if pid != current:
                current = pid
                html = next((p.get("devMetadata", {}).get("htmlSrc", "") for p in page_items(design) if p.get("id") == pid), "")
                print(f"=== {pid} | {title} | {html} ===")
            print(f"  {dom} -> {target}")
        print(f"\n{len(rows)} interaction(s)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
