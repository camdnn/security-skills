#!/usr/bin/env python3
"""List likely Express route registrations without executing target code."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROUTE = re.compile(
    r"\b(?P<receiver>app|router)\s*\.\s*(?P<method>get|post|put|patch|delete|all|use)"
    r"\s*\(\s*(?P<quote>['\"])(?P<path>.*?)(?P=quote)",
    re.IGNORECASE,
)
SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"}
IGNORED_PARTS = {"node_modules", ".git", "dist", "build", "coverage"}


def find_entry_points(root: Path) -> list[dict[str, object]]:
    """Return deterministic route metadata with paths relative to *root*."""

    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in path.relative_to(root).parts):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in ROUTE.finditer(content):
            entries.append(
                {
                    "file": path.relative_to(root).as_posix(),
                    "line": content.count("\n", 0, match.start()) + 1,
                    "receiver": match["receiver"].lower(),
                    "method": match["method"].lower(),
                    "path": match["path"],
                }
            )
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="target project root")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {args.root}")
    print(json.dumps(find_entry_points(root), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
