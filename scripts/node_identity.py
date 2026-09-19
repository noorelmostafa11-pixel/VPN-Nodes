#!/usr/bin/env python3
"""URI identity used for duplicate-node removal.

Project policy: the fragment after the first '#' is only a display remark and
must not create a distinct node. Everything before '#' is compared literally:
no parameter reordering, default normalization, transport normalization, or
other semantic equivalence is applied.
"""
from __future__ import annotations


def dedup_key(uri: str) -> str:
    """Return the URI before the first '#'; keep every other textual difference."""
    return uri.split("#", 1)[0]
