"""Reading in-scope files, including gzip (CloudTrail's default S3 delivery format), with a size limit that also
covers the DECOMPRESSED size so a small archive cannot expand without bound."""
from __future__ import annotations

import gzip
from pathlib import Path

OTHER_COMPRESSED = (".bz2", ".xz", ".zst", ".zip", ".tgz", ".tar", ".7z")


class Unreadable(Exception):
    """The file cannot be read as text within the limit; the message is the reason that gets logged."""


def inner_name(name: str) -> str:
    """File name used for classification: `trail.json.gz` is judged as `trail.json`."""
    return name[:-3] if name.lower().endswith(".gz") else name


def is_other_compressed(name: str) -> bool:
    n = name.lower()
    return n.endswith(OTHER_COMPRESSED) or n.endswith((".tar.gz",))


def read_text(path: Path, limit: int, errors: str = "strict") -> str:
    if path.name.lower().endswith(".gz"):
        try:
            with gzip.open(path, "rb") as fh:
                raw = fh.read(limit + 1)
        except (OSError, EOFError, gzip.BadGzipFile) as e:
            raise Unreadable(f"not a readable gzip file ({type(e).__name__})") from e
        if len(raw) > limit:
            raise Unreadable(f"uncompressed content is over the {limit} byte cap (raise it with --max-bytes)")
        return raw.decode("utf-8", errors=errors)
    return path.read_text(encoding="utf-8", errors=errors)
