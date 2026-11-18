#!/usr/bin/env python3
"""Report context module files whose recorded coverage changed since their commit."""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path


def front_matter(text: str) -> dict[str, object]:
    """Read the small YAML subset emitted by the module template."""

    if not text.startswith("---\n"):
        return {}
    closing = text.find("\n---", 4)
    if closing < 0:
        return {}
    values: dict[str, object] = {}
    key: str | None = None
    for raw in text[4:closing].splitlines():
        if raw.startswith("  - ") and key == "covers":
            values.setdefault("covers", []).append(raw[4:].strip())
        elif ":" in raw:
            key, value = (item.strip() for item in raw.split(":", 1))
            values[key] = [] if key == "covers" and not value else value
    return values


def changed_paths(root: Path, commit: str) -> set[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{commit}..HEAD", "--"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return set()
    return {line for line in result.stdout.splitlines() if line}


def covered(pattern: str, path: str) -> bool:
    """Return whether a ``covers:`` entry (file, folder or glob) includes ``path``."""

    pattern = pattern.strip().strip("\"'")
    if any(character in pattern for character in "*?["):
        return fnmatch.fnmatchcase(path, pattern)
    folder = pattern.rstrip("/")
    return path == folder or path.startswith(folder + "/")


def stale_modules(root: Path) -> list[dict[str, object]]:
    modules = root / "docs/security/modules"
    if not modules.is_dir():
        return []
    stale: list[dict[str, object]] = []
    for module in sorted(modules.glob("*.md")):
        metadata = front_matter(module.read_text(encoding="utf-8"))
        commit = metadata.get("commit")
        covers = metadata.get("covers", [])
        if not isinstance(commit, str) or not commit or commit == "unknown":
            stale.append({"module": module.relative_to(root).as_posix(), "reason": "missing commit"})
            continue
        if not isinstance(covers, list):
            covers = []
        changed = sorted(path for path in changed_paths(root, commit) if any(covered(str(p), path) for p in covers))
        if changed:
            stale.append({"module": module.relative_to(root).as_posix(), "changed_paths": changed})
    return stale


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="target project root")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {args.root}")
    print(json.dumps(stale_modules(root), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
