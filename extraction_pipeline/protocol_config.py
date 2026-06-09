#!/usr/bin/env python3
"""Phase 0 protocol constants for ContextDroid.

This file is intentionally configuration-only and does not change runtime behavior
until future phases explicitly wire these values into execution paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


# Execution modes (future phases will wire these into orchestrators/CLI).
MODE_LLM_ONLY: Final[str] = "llm_only"
MODE_LLM_PLUS_MONKEY: Final[str] = "llm_plus_monkey"
SUPPORTED_MODES: Final[tuple[str, ...]] = (MODE_LLM_ONLY, MODE_LLM_PLUS_MONKEY)


# Session protocol constants.
SESSION_DURATION_SEC: Final[int] = 120
SESSIONS_PER_APP_PER_ARM: Final[int] = 3
DEFAULT_SESSIONS_LLM_ONLY: Final[int] = 1
SESSION_TIMEOUT_MULTIPLIER: Final[int] = 3
SESSION_TIMEOUT_SEC: Final[int] = SESSION_DURATION_SEC * SESSION_TIMEOUT_MULTIPLIER


# Pre-simulation onboarding warmup constants.
PRE_ONBOARDING_MONKEY_SEED: Final[int] = 42
PRE_ONBOARDING_MONKEY_EVENTS: Final[int] = 10
PRE_ONBOARDING_WARMUP_SEC: Final[int] = 15


# LLM reproducibility constants.
LLM_TEMPERATURE: Final[float] = 0.0
ACTION_HISTORY_WINDOW: Final[int] = 3
PROMPT_HASH_ALGO: Final[str] = "sha256"


# XML preprocessing/token budget constants.
MAX_DESCRIPTION_CHARS: Final[int] = 1000
MAX_PERMISSION_HINTS: Final[int] = 20
MAX_API_HINTS: Final[int] = 50
MAX_AGENT_XML_TOKENS: Final[int] = 2000


# Guardrail constants.
REPETITION_WINDOW: Final[int] = 5
REPETITION_THRESHOLD: Final[int] = 3
STAGNATION_CONSECUTIVE_FOR_BACK: Final[int] = 3
STAGNATION_CONSECUTIVE_FOR_BAILOUT: Final[int] = 5


# Metric constants.
SEQUENCE_NGRAM_N: Final[int] = 3  # API-name trigrams


# Additive-only default field values for legacy rows.
DEFAULT_ARM: Final[str] = "unknown"
DEFAULT_METADATA_SOURCE: Final[str] = "unknown"
DEFAULT_CONTEXT_CONFIDENCE: Final[str] = "unknown"


# Enumerations for statuses/labels used in future phases.
VALID_METADATA_SOURCES: Final[tuple[str, ...]] = ("google_play", "fdroid", "apk_only", "unknown")
VALID_CONTEXT_CONFIDENCE: Final[tuple[str, ...]] = ("high", "medium", "low", "unknown")
VALID_ARM_VALUES: Final[tuple[str, ...]] = ("llm", "monkey", "unknown")

SKIP_REASON_UNSTABLE: Final[str] = "unstable"
SKIP_REASON_LOGIN_REQUIRED: Final[str] = "login_required"
SKIP_REASON_ANTI_EMULATOR: Final[str] = "anti_emulator"
FLAG_WEBVIEW_DOMINANT: Final[str] = "webview_dominant"

PARTIAL_AGENT_STUCK: Final[str] = "agent_stuck"
PARTIAL_TIMEOUT: Final[str] = "timeout"
PARTIAL_OLLAMA_UNAVAILABLE: Final[str] = "ollama_unavailable"

OLLAMA_GENERATE_RETRIES: Final[int] = 3
OLLAMA_GENERATE_RETRY_BASE_SEC: Final[float] = 0.35
# Bail after this many planner steps where every Ollama retry failed (avoid false agent_stuck).
OLLAMA_DEAD_AFTER_CONSECUTIVE_STEPS: Final[int] = 3


@dataclass(frozen=True)
class QueueConfig:
    """Queue policy constants for dynamic runtime app discovery."""

    runtime_scan_glob: str = "*.apk"
    deterministic_sort: bool = True
    full_run_directory: str = "data/apks/benign"
    # Pilot-only controls are optional overlays in future phases.
    pilot_min_apps: int = 20
    pilot_max_apps: int = 30

