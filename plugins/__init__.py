"""Plugin registry — loads and returns all built-in plugin panels."""
from __future__ import annotations


def load_all(session) -> list:
    """Load all plugins and return their QDockWidget panel instances."""
    panels = []
    try:
        from plugins.mona import activate
        from plugins.mona.panel import MonaPanel
        activate()
        panels.append(MonaPanel(session))
    except Exception as exc:
        print(f"[plugins] mona load failed: {exc}")
    try:
        from plugins.analysis.panel import AnalysisPanel
        panels.append(AnalysisPanel(session))
    except Exception as exc:
        print(f"[plugins] analysis load failed: {exc}")
    return panels
