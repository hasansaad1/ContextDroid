"""Shared pipeline failure types (importable without analyze_apk ↔ llm_agent cycles)."""

from __future__ import annotations


class AnalysisFailure(RuntimeError):
    def __init__(self, reason: str, exit_code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.exit_code = exit_code
