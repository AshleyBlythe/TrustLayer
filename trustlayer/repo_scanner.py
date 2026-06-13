"""Repo scanner: walks a local directory tree and applies heuristic checks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .checks import (
    check_admin_routes,
    check_api_docs,
    check_committed_env,
    check_cors,
    check_debug_routes,
    check_demo_credentials,
    check_manifest,
    check_public_env_vars,
    check_secrets,
    check_sensitive_files,
    check_sensitive_in_public,
    check_source_maps,
    check_supabase,
)
from .models import ScanResult

# Directories that are never useful to scan
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", ".venv", "venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", ".next", ".nuxt", ".output",
    ".idea", ".vscode",
})

# File extensions that are binary or otherwise unreadable as text
_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".avif",
    ".mp4", ".mp3", ".wav", ".ogg", ".webm", ".mov", ".avi",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".class",
    ".db", ".sqlite", ".sqlite3",
    ".parquet", ".arrow",
})

MAX_FILE_BYTES = 512 * 1024  # 512 KB per file


def scan_repo(root: str, result: Optional[ScanResult] = None) -> ScanResult:
    root_path = Path(root).resolve()
    if result is None:
        result = ScanResult(target=str(root_path))

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            rel_path = file_path.relative_to(root_path)
            source = str(rel_path)

            # Always run path-based checks regardless of readability
            result.findings.extend(check_committed_env(file_path, source))
            result.findings.extend(check_sensitive_in_public(file_path, source))
            result.findings.extend(check_sensitive_files(file_path, source))
            result.findings.extend(check_manifest(file_path, source))

            ext = file_path.suffix.lower()
            if ext in _BINARY_EXTENSIONS:
                result.skipped_files += 1
                continue

            try:
                size = file_path.stat().st_size
            except OSError:
                result.skipped_files += 1
                continue

            if size > MAX_FILE_BYTES:
                result.skipped_files += 1
                continue

            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                result.errors.append(f"Could not read {source}: {exc}")
                result.skipped_files += 1
                continue

            lines = text.splitlines(keepends=False)
            result.scanned_files += 1

            # Content-based checks
            result.findings.extend(check_secrets(lines, source))
            result.findings.extend(check_public_env_vars(lines, source))
            result.findings.extend(check_admin_routes(lines, source))
            result.findings.extend(check_debug_routes(lines, source))
            result.findings.extend(check_source_maps(file_path, lines, source))
            result.findings.extend(check_cors(lines, source))
            result.findings.extend(check_demo_credentials(lines, source))
            result.findings.extend(check_api_docs(lines, file_path, source))
            result.findings.extend(check_supabase(lines, source))

    return result
