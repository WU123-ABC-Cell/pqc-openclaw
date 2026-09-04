#!/usr/bin/env python3
"""Regression guard v2: detect pnpm/action-setup + packageManager trap.

Two failure modes:
(A) EXPLICIT_CONFLICT: `version: X` in `with:` + packageManager in package.json.
    → ERR_PNPM_BAD_PM_VERSION
(B) AMBIGUOUS_YAML: empty `with:` followed by same-indent next step.
    → 0-second failure (no jobs run)

Fix: drop explicit `version:`; never leave `with:` empty (omit the line).
"""
import re
import sys
import json
from pathlib import Path


def check_file(workflow_path: Path, package_json: dict) -> list[str]:
    """Check a single workflow file for pnpm trap violations."""
    issues = []
    text = workflow_path.read_text(encoding="utf-8")

    if "pnpm/action-setup@" not in text:
        return []

    # State machine:
    #   in_pnpm_block: True when we just saw a `uses: pnpm/action-setup@` line
    #   pnpm_uses_indent: the leading-space count of that uses line (= content indent for that step)
    #   pnpm_with_indent: leading-space count of the `with:` line (or None)
    #   has_version: True if we saw `version: X` inside the with: block
    #   has_empty_with: True if `with:` was followed by another step at the same indent
    lines = text.split("\n")
    in_pnpm_block = False
    pnpm_uses_indent = None
    pnpm_with_indent = None
    has_version = False
    has_empty_with = False

    def flush(where: str) -> None:
        """At end of pnpm block, emit any issues found."""
        nonlocal has_version, has_empty_with, in_pnpm_block
        if has_empty_with:
            issues.append(
                f"{workflow_path}:{where} AMBIGUOUS_YAML: "
                f"pnpm/action-setup has empty `with:` block followed by same-indent next step. "
                f"GitHub's parser rejects this as ambiguous YAML → 0-second failure "
                f"(0 jobs executed). Fix: remove the `with:` line entirely."
            )
        if has_version and package_json.get("packageManager", "").startswith("pnpm@"):
            pm = package_json.get("packageManager", "")
            issues.append(
                f"{workflow_path}:{where} EXPLICIT_CONFLICT: "
                f"pnpm/action-setup has `version:` in `with:` AND "
                f"package.json has packageManager: {pm}. "
                f"action errors with 'Multiple versions of pnpm specified' "
                f"(ERR_PNPM_BAD_PM_VERSION). Fix: remove `version:` line, "
                f"let action read from packageManager."
            )
        in_pnpm_block = False
        pnpm_uses_indent = None
        pnpm_with_indent = None
        has_version = False
        has_empty_with = False

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Detect the `uses: pnpm/action-setup@...` line
        m = re.match(r"^(\s*)uses:\s*pnpm/action-setup@", line)
        if m:
            # Flush any previous pnpm block (shouldn't happen but safe)
            if in_pnpm_block:
                flush(f"L{i}")
            in_pnpm_block = True
            pnpm_uses_indent = len(m.group(1))
            pnpm_with_indent = None
            has_version = False
            has_empty_with = False
            continue

        if not in_pnpm_block:
            continue

        leading_spaces = len(line) - len(stripped)

        # End of pnpm block: a line at the same indent as a top-level `- name: ...`
        # i.e. leading_spaces <= pnpm_uses_indent - 2 (because uses is indented 2 from `-`)
        # OR a line at pnpm_uses_indent (a sibling uses/with that starts a new step — shouldn't happen)
        if leading_spaces <= pnpm_uses_indent - 2 and stripped:
            flush(f"L{i}")
            continue

        # Inside pnpm block. Look for `with:` line.
        if re.match(r"^\s*with:\s*$", line):
            pnpm_with_indent = leading_spaces
            # Look ahead to see if `with:` is empty (followed by next step at uses_indent - 2)
            for j in range(i + 1, len(lines)):
                next_line = lines[j]
                next_stripped = next_line.lstrip()
                if not next_stripped:
                    continue
                next_indent = len(next_line) - len(next_stripped)
                # A non-empty with: has children at with_indent + 2 (= pnpm_uses_indent)
                # An empty with: has its sibling step at pnpm_uses_indent - 2 or less
                if next_indent <= pnpm_uses_indent - 2:
                    has_empty_with = True
                break
            continue

        # Inside with: block: check for `version: X`
        if pnpm_with_indent is not None and leading_spaces > pnpm_with_indent:
            if re.match(r"^\s*version:\s*\d", line):
                has_version = True

    if in_pnpm_block:
        flush("EOF")

    return issues


def main() -> int:
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    else:
        root = Path(".")

    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.exists():
        print(f"ERROR: {workflows_dir} not found", file=sys.stderr)
        return 1

    pkg_path = root / "package.json"
    if not pkg_path.exists():
        print(f"ERROR: {pkg_path} not found", file=sys.stderr)
        return 1
    package_json = json.loads(pkg_path.read_text(encoding="utf-8"))

    workflow_files = sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml"))
    if not workflow_files:
        print(f"WARNING: no workflow files in {workflows_dir}", file=sys.stderr)
        return 0

    all_issues = []
    used_pnpm_count = 0
    for wf in workflow_files:
        if "pnpm/action-setup@" in wf.read_text(encoding="utf-8"):
            used_pnpm_count += 1
        issues = check_file(wf, package_json)
        all_issues.extend(issues)

    if all_issues:
        print("=" * 60, file=sys.stderr)
        print(f"FAIL: {len(all_issues)} pnpm/action-setup trap violation(s) found", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for issue in all_issues:
            print(f"  {issue}", file=sys.stderr)
        print("", file=sys.stderr)
        print("See .github/scripts/check-pnpm-action-setup.py header for fix details.", file=sys.stderr)
        return 1

    print(f"OK: {len(workflow_files)} workflow files checked, {used_pnpm_count} use pnpm/action-setup, 0 violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
