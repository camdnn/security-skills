"""Tests for static helpers used by the Week 3 context workflow."""

import subprocess
from importlib import util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "skills/security-scan/scripts" / name
    spec = util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_find_entry_points_finds_routes_and_ignores_node_modules(tmp_path: Path):
    (tmp_path / "routes.ts").write_text("app.get('/orders', handler);\nrouter.post(\"/refunds\", save);\n")
    dependency = tmp_path / "node_modules/pkg"
    dependency.mkdir(parents=True)
    (dependency / "routes.js").write_text("app.delete('/ignored', remove);\n")

    entries = load_script("find_entry_points.py").find_entry_points(tmp_path)

    assert entries == [
        {"file": "routes.ts", "line": 1, "receiver": "app", "method": "get", "path": "/orders"},
        {"file": "routes.ts", "line": 2, "receiver": "router", "method": "post", "path": "/refunds"},
    ]


def test_stale_modules_reports_covered_file_changed_since_recorded_commit(tmp_path: Path):
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    source = tmp_path / "routes.ts"
    source.write_text("export const route = 1;\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=tmp_path, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    module_dir = tmp_path / "docs/security/modules"
    module_dir.mkdir(parents=True)
    (module_dir / "orders.md").write_text(f"---\ncovers:\n  - routes.ts\ncommit: {commit}\n---\n# Orders\n")
    source.write_text("export const route = 2;\n")
    subprocess.run(["git", "add", "routes.ts"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "change route"], cwd=tmp_path, check=True)

    stale = load_script("stale_modules.py").stale_modules(tmp_path)

    assert stale == [{"module": "docs/security/modules/orders.md", "changed_paths": ["routes.ts"]}]


def test_stale_modules_matches_folders_and_globs_in_covers():
    covered = load_script("stale_modules.py").covered

    assert covered("routes/**", "routes/admin/users.ts")
    assert covered("routes/*.ts", "routes/orders.ts")
    assert covered("routes/", "routes/orders.ts")
    assert covered("routes", "routes/orders.ts")
    assert covered("server.ts", "server.ts")
    assert not covered("routes", "routes-old/orders.ts")
    assert not covered("lib/**", "routes/orders.ts")
