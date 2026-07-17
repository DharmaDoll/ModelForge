"""Deterministic identifier helpers for model entities."""

from __future__ import annotations

import hashlib
import re

_NON_ID_CHARS = re.compile(r"[^a-z0-9]+")


def slugify(value: object, *, fallback: str = "unknown") -> str:
    """Return a stable lowercase slug safe for JSON references and Mermaid aliases."""

    text = str(value or "").strip().lower()
    slug = _NON_ID_CHARS.sub("-", text).strip("-")
    return slug or fallback


def make_id(kind: str, *parts: object, max_part_length: int = 80) -> str:
    """Build a deterministic colon-delimited model identifier."""

    clean_parts = [slugify(kind)]
    for part in parts:
        clean = slugify(part)
        if len(clean) > max_part_length:
            digest = hashlib.sha1(clean.encode("utf-8")).hexdigest()[:10]
            clean = f"{clean[: max_part_length - 11]}-{digest}"
        clean_parts.append(clean)
    return ":".join(clean_parts)


def short_hash(*parts: object, length: int = 10) -> str:
    """Return a short deterministic hash for compact generated identifiers."""

    joined = "\x1f".join(str(part) for part in parts)
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:length]
