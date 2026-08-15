---
name: src-line-limit
description: Use after code changes to check changed source files, before reporting completion, and when auditing all source files or comparing a branch with a base ref.
---

# Source Line Limit

Check physical line counts for UTF-8 text files whose path contains a component named exactly `src`.

## Run From Any Worktree Or Subdirectory

Resolve the current worktree root before invoking the project-local script:

```bash
repo_root="$(git rev-parse --show-toplevel)"
python3 "$repo_root/.codex/skills/src-line-limit/scripts/check_src_lines.py"
```

The default mode checks existing staged, unstaged, and untracked non-ignored files relative to `HEAD`. It does not scan unchanged files.

Use `--base` to include files changed by branch commits as well as current worktree changes:

```bash
python3 "$repo_root/.codex/skills/src-line-limit/scripts/check_src_lines.py" --base origin/dev
```

Use `--all` to check every Git tracked file plus every untracked non-ignored file:

```bash
python3 "$repo_root/.codex/skills/src-line-limit/scripts/check_src_lines.py" --all
```

`--all` and `--base` are mutually exclusive. `--root PATH` may be used to select a Git worktree explicitly, primarily for tests and automation.

## Limits And Exit Codes

- 0-300 lines: accepted.
- 301-500 lines: `WARNING`; exit status remains `0`.
- More than 500 lines: `ERROR`; exit status is `1`.
- Invalid arguments, an invalid repository root, or a failed Git operation: exit status `2`.

Empty files have zero lines. A final line without a trailing newline still counts as one physical line. Missing files, non-regular files, binary files, and files that are not valid UTF-8 are skipped.

## Reporting Obligations

Record every 301-500 line warning in the change summary. For every file above 500 lines, split or refactor it before completion unless the user explicitly accepts an exception; record that exception in the change summary. A status of `1` is a line-limit finding, not a tool execution failure.
