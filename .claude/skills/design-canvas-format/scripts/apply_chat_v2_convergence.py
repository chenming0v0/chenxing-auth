#!/usr/bin/env python3
"""Re-apply chat-interface-v2 version convergence (see interactions.md §2).

SOLO Design 画布若以旧内存态保存，会把聊天页连线写回旧图（复活已删除的
page-chat-interface 节点、入线指回旧页）。本脚本一键恢复收敛结果：
  1) 删除复活的 page-chat-interface 节点（2026-07-26 起旧页已从画布彻底移除）
  2) 所有仍指向 page-chat-interface 的入线改指 page-chat-interface-v2
  3) page-chat-interface-v2 出线 = back-to-list(hideEdge) / open-model-picker
     / open-tool-panel / open-msg-menu
跑完后用 validate_interactions.py 复核（REMOVED_PAGE_IDS 会兜底报警）。
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from design_common import default_design_path, load_design, save_design

OLD_ID = "page-chat-interface"
NEW_ID = "page-chat-interface-v2"
V2_INTERACTIONS = [
    {"domId": "back-to-list", "targetPageId": "page-chat-list", "hideEdge": True, "transitionLabel": "返回"},
    {"domId": "open-model-picker", "targetPageId": "page-model-picker"},
    {"domId": "open-tool-panel", "targetPageId": "page-tool-panel"},
    {"domId": "open-msg-menu", "targetPageId": "page-msg-context-menu"},
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Re-apply chat v2 convergence")
    parser.add_argument("--design", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    path = default_design_path() if not args.design else Path(args.design)
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 1
    design = load_design(path)
    data = design.get("data", [])
    revived = sum(1 for item in data if item.get("id") == OLD_ID)
    design["data"] = [item for item in data if item.get("id") != OLD_ID]
    redirected = 0
    for item in design["data"]:
        meta = item.setdefault("devMetadata", {})
        if item.get("id") == NEW_ID:
            meta["interactions"] = V2_INTERACTIONS
        else:
            for inter in meta.get("interactions", []) or []:
                if inter.get("targetPageId") == OLD_ID:
                    inter["targetPageId"] = NEW_ID
                    redirected += 1
    if args.dry_run:
        print(f"Would drop {revived} revived `{OLD_ID}` node(s); redirect {redirected} incoming edge(s); rewire {NEW_ID}")
        return 0
    save_design(path, design)
    print(f"Converged: dropped {revived} `{OLD_ID}` node(s); redirected {redirected} incoming edge(s); {NEW_ID} wired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
