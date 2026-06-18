"""Mona plugin package — Corelan mona.py integration."""
from __future__ import annotations
from .bridge import _ensure_immlib_stub


def activate() -> None:
    """Pre-inject immlib stub so mona can be imported without a real debugger."""
    _ensure_immlib_stub()
