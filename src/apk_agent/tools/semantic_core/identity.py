"""Stable semantic identity helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def normalize_descriptor(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def normalize_field_source(class_name: str, field_name: str, field_type: str = "") -> str:
    base = f"{normalize_descriptor(class_name)}->{normalize_descriptor(field_name)}"
    if field_type:
        return f"{base}:{normalize_descriptor(field_type)}"
    return base


def normalize_method_source(full_signature: str) -> str:
    return normalize_descriptor(full_signature)


def canonical_payload(*parts: Any) -> str:
    return json.dumps(parts, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def stable_identity(prefix: str, *parts: Any) -> str:
    digest = hashlib.sha1(canonical_payload(*parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}:{digest}"