"""Scope guard: the agent may only read local files inside an approved root.

Assay never opens sockets to targets, never runs scanners against hosts and never
follows symlinks out of the root. Anything that looks like a network target is
refused before any work starts.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
HOSTPORT_RE = re.compile(r"^[\w.-]+:\d+$")

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", "dist", "build"}
MAX_FILE_BYTES = 1_000_000


class ScopeError(ValueError):
    pass


def _looks_like_network_target(target: str) -> bool:
    if URL_RE.match(target) or HOSTPORT_RE.match(target):
        return True
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Scope:
    root: Path

    @classmethod
    def from_target(cls, target: str) -> "Scope":
        if _looks_like_network_target(target):
            raise ScopeError(
                f"refused: '{target}' looks like a network target. Assay only reviews local files "
                "you own or are licensed to test; it never scans hosts."
            )
        root = Path(target).expanduser().resolve()
        if not root.is_dir():
            raise ScopeError(f"refused: '{target}' is not a local directory")
        return cls(root)

    def contains(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.root)
            return True
        except ValueError:
            return False

    def files(self):
        """Yield in-scope regular files (no symlinks escaping the root, no huge files)."""
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.is_symlink() and not self.contains(p):
                    continue
                if not p.is_file() or not self.contains(p):
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                yield p

    def rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()
