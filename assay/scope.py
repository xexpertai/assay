"""Scope guard: the agent may only read local files inside an approved root.

Assay never opens sockets to targets, never runs scanners against hosts and never
follows symlinks out of the root. Anything that looks like a network target is
refused before any work starts.

`ScopePolicy` states what *hosts* may appear in the assessment at all:
- `files-only` (default): no host is in scope; tool-output files are still read as local
  evidence, but no active step can ever be authorised.
- `lab-allowlist`: an explicit, time-limited, named-owner allowlist loaded from a lab file.
  Evidence about hosts outside it is dropped, and an active step is allowed only for a
  listed host, only with a recorded human approval. The library ships no active runners;
  the gate exists so that any runner added later cannot bypass it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import date
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


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ScopePolicy:
    mode: str = "files-only"  # files-only | lab-allowlist
    name: str = ""
    hosts: frozenset[str] = frozenset()  # exact hostnames / addresses
    networks: tuple = ()  # ipaddress networks
    authorised_by: str = ""
    expires: str = ""  # ISO date, inclusive
    source: str = ""
    source_sha256: str = ""

    @classmethod
    def files_only(cls) -> "ScopePolicy":
        return cls()

    @classmethod
    def from_lab_file(cls, path: str | Path, today: date | None = None) -> "ScopePolicy":
        """Load an allowlist. Required: name, authorised_by, expires (YYYY-MM-DD), hosts and/or networks."""
        p = Path(path).expanduser()
        if not p.is_file():
            raise PolicyError(f"refused: lab file '{path}' not found")
        raw = p.read_bytes()
        try:
            d = json.loads(raw)
        except json.JSONDecodeError as e:
            raise PolicyError(f"refused: lab file is not valid JSON ({e.msg})")
        for key in ("name", "authorised_by", "expires"):
            if not str(d.get(key, "")).strip():
                raise PolicyError(f"refused: lab file must state '{key}'")
        try:
            exp = date.fromisoformat(d["expires"])
        except ValueError:
            raise PolicyError("refused: lab file 'expires' must be YYYY-MM-DD")
        if exp < (today or date.today()):
            raise PolicyError(f"refused: lab authorisation '{d['name']}' expired on {d['expires']}")
        nets = []
        for n in d.get("networks") or []:
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                raise PolicyError(f"refused: bad network '{n}' in lab file")
        hosts = frozenset(str(h).strip().lower() for h in (d.get("hosts") or []) if str(h).strip())
        if not hosts and not nets:
            raise PolicyError("refused: lab file lists no hosts and no networks")
        return cls("lab-allowlist", str(d["name"]), hosts, tuple(nets), str(d["authorised_by"]), d["expires"],
                   str(p), hashlib.sha256(raw).hexdigest())

    def permits_host(self, host: str, names: list[str] | None = None) -> tuple[bool, str]:
        """May evidence about this host be used? (allowed, reason)."""
        if self.mode == "files-only":
            return True, "files-only mode: evidence files are read, no host is ever contacted"
        cands = {host.lower(), *(n.lower() for n in (names or []))}
        if cands & self.hosts:
            return True, f"host listed in lab '{self.name}'"
        try:
            ip = ipaddress.ip_address(host)
            for n in self.networks:
                if ip in n:
                    return True, f"address inside {n} in lab '{self.name}'"
        except ValueError:
            pass
        return False, f"host {host} is not in lab '{self.name}' allowlist; evidence dropped"

    def authorise_active(self, host: str, action: str, approver: str | None) -> str:
        """Gate for any future active step. Returns the reason string or raises PolicyError."""
        if self.mode != "lab-allowlist":
            raise PolicyError(f"refused: active step '{action}' on {host}: policy is files-only")
        ok, why = self.permits_host(host)
        if not ok:
            raise PolicyError(f"refused: active step '{action}': {why}")
        if not approver or not approver.strip():
            raise PolicyError(f"refused: active step '{action}' on {host} needs a named human approval")
        return f"{action} on {host} permitted: {why}; approved by {approver.strip()}"

    def to_dict(self) -> dict:
        return {"mode": self.mode, "name": self.name, "hosts": sorted(self.hosts),
                "networks": [str(n) for n in self.networks], "authorised_by": self.authorised_by,
                "expires": self.expires, "source": self.source, "source_sha256": self.source_sha256}
