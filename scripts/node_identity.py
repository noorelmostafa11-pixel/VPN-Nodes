#!/usr/bin/env python3
"""Exact URI identity for node deduplication.

Project policy: only text-identical URI strings are duplicates.
No parameter reordering, default normalization, remark removal, transport
normalization, or other semantic equivalence is applied.
"""
from __future__ import annotations


def dedup_key(uri: str) -> str:
    """Return the URI unchanged so only exact URI matches deduplicate."""
    return uri
