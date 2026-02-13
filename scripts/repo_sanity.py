#!/usr/bin/env python3
"""Repository sanity checks.

Fails when runtime artifacts are tracked in git.
"""

from __future__ import annotations

import subprocess
import sys
from fnmatch import fnmatch

FORBIDDEN_TRACKED_PATTERNS = (
    "reports/**",
    "data/*.db",
    "data/*.db-*",
)


def tracked_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True)
    return [line.strip() for line in out.splitlines() if line.strip()]


def main() -> int:
    offenders: list[str] = []
    for path in tracked_files():
        if any(fnmatch(path, pattern) for pattern in FORBIDDEN_TRACKED_PATTERNS):
            offenders.append(path)

    if offenders:
        print("repo_sanity failed: tracked runtime artifacts detected.", file=sys.stderr)
        for path in offenders:
            print(f" - {path}", file=sys.stderr)
        print("Move runtime outputs under .runtime/ (ignored) and untrack them.", file=sys.stderr)
        return 1

    print("repo_sanity passed: no tracked runtime artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
