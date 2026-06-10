from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from fastguard.models import FileGroup


_FILE_GROUP_PATTERNS: dict[FileGroup, list[str]] = {
    FileGroup.ROUTES: [
        "route", "router", "endpoint", "api", "view", "controller",
        "handler", "urls", "rout", "resource",
    ],
    FileGroup.MODELS: [
        "model", "schema", "schemas", "pydantic", "serializer",
        "dto", "dataclass", "entity", "models",
    ],
    FileGroup.CONFIG: [
        "config", "setting", "env", "environment", "constant",
        "secret", "conf", "pyproject", "requirements",
    ],
    FileGroup.MIDDLEWARE: [
        "middleware", "middle", "interceptor", "filter",
    ],
    FileGroup.AUTH: [
        "auth", "authn", "authz", "permission", "role", "user",
        "jwt", "oauth", "login", "token", "session", "dependency",
        "dependencies", "guard",
    ],
    FileGroup.MAIN: [
        "main", "app", "application", "server", "entry", "startup",
        "wsgi", "asgi", "run",
    ],
}


def classify_file(filepath: str) -> FileGroup:
    path = Path(filepath)
    stem = path.stem.lower()
    parent = path.parent.name.lower()

    candidates = [stem, parent]
    for group, patterns in _FILE_GROUP_PATTERNS.items():
        for candidate in candidates:
            for pattern in patterns:
                if pattern in candidate:
                    return group

    return FileGroup.OTHER


def collect_files(target_dir: str, include_pyproject: bool = True) -> Dict[FileGroup, List[str]]:
    target = Path(target_dir).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"Target is not a directory: {target}")

    groups: Dict[FileGroup, List[str]] = {g: [] for g in FileGroup}
    seen: set[str] = set()

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__" and d != "node_modules" and d != "venv" and d != ".venv"]

        for fname in files:
            if fname.endswith(".py") or (include_pyproject and fname in ("requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock")):
                full = os.path.join(root, fname)
                if full in seen:
                    continue
                seen.add(full)
                group = classify_file(full)
                groups[group].append(full)

    for g in list(groups.keys()):
        groups[g] = sorted(groups[g])

    return groups


def read_file_content(filepath: str) -> str:
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"# Error reading {filepath}: {e}"


def group_to_code_blocks(groups: Dict[FileGroup, List[str]]) -> Dict[FileGroup, str]:
    result: Dict[FileGroup, str] = {}
    for group, files in groups.items():
        if not files:
            continue
        blocks: list[str] = []
        for fpath in files:
            content = read_file_content(fpath)
            relpath = os.path.relpath(fpath) if not fpath.startswith("/") else fpath
            blocks.append(f"# --- File: {relpath} ---\n{content}")
        result[group] = "\n\n".join(blocks)
    return result
