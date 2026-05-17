"""Analyzer base class + safe-string helpers.

Every analyzer returns a list of Evidence. Never let raw bytes from a sample
reach the LLM — sanitize through `safe_string` before exposing string fields.
"""
from __future__ import annotations
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..types import Evidence

# Strip control chars and anything that looks like prompt-injection scaffolding.
_PROMPT_INJECTION = re.compile(
    r"(?:system:|assistant:|<\|.*?\|>|```|"
    r"ignore (?:the )?(?:previous|above|prior)|new instructions|"
    r"you are now|forget everything|disregard)",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe_string(s: Any, max_len: int = 200) -> str:
    """Sanitize a string field destined for analyst display or LLM context.

    - Coerces to str.
    - Strips control chars and replaces prompt-injection patterns with [REDACTED].
    - Truncates to `max_len` to keep evidence compact in LLM context.
    """
    text = str(s)
    text = _CONTROL.sub("", text)
    text = _PROMPT_INJECTION.sub("[REDACTED]", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def safe_list(items: list[Any], max_items: int = 50, max_len: int = 200) -> list[str]:
    return [safe_string(i, max_len) for i in items[:max_items]]


class FileAnalyzer(ABC):
    """Analyzes a file on disk and returns structured Evidence."""

    name: str = ""

    @abstractmethod
    def supports(self, path: Path, magic_type: str) -> bool:
        """Should this analyzer run on this file?"""

    @abstractmethod
    def analyze(self, path: Path) -> list[Evidence]:
        ...


class StringAnalyzer(ABC):
    """Analyzes a URL / IP / domain / hash string."""

    name: str = ""

    @abstractmethod
    def analyze(self, value: str) -> list[Evidence]:
        ...
