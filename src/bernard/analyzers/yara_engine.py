"""YARA-X integration.

Loads precompiled YARA-Forge rules from `rules/yara-forge/` (downloaded by
`scripts/bootstrap_yara.py`) and exposes a `match(path)` method that returns
structured Evidence per rule hit.

YARA-X is the 2026-stable Rust rewrite of YARA — same rule syntax, faster,
cleaner Python API.
"""
from __future__ import annotations
from pathlib import Path
from typing import Iterable

from ..config import CONFIG
from ..types import Evidence, Severity
from .base import safe_string

# Rule severity heuristic from rule metadata + name patterns
_HIGH_SEVERITY_PATTERNS = ("ransom", "rat_", "stealer", "backdoor", "wiper", "rootkit", "implant", "loader_")
_MEDIUM_SEVERITY_PATTERNS = ("downloader", "packed", "anti_", "suspicious", "info_stealer")


def _classify_severity(rule_name: str, metadata: dict) -> Severity:
    score = metadata.get("score") or metadata.get("severity")
    if isinstance(score, int):
        if score >= 80:
            return Severity.CRITICAL
        if score >= 60:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        return Severity.LOW
    name_lower = rule_name.lower()
    if any(p in name_lower for p in _HIGH_SEVERITY_PATTERNS):
        return Severity.HIGH
    if any(p in name_lower for p in _MEDIUM_SEVERITY_PATTERNS):
        return Severity.MEDIUM
    return Severity.LOW


class YaraEngine:
    """Loads YARA-X rules once and matches files against them."""

    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir or CONFIG.storage.rules_dir / "yara-forge"
        self._scanner = None
        self._loaded_rule_files: list[str] = []

    def _ensure_loaded(self) -> bool:
        if self._scanner is not None:
            return True
        try:
            import yara_x
        except ImportError:
            return False

        if not self.rules_dir.exists():
            return False

        rule_files = sorted(self.rules_dir.rglob("*.yar")) + sorted(self.rules_dir.rglob("*.yara"))
        if not rule_files:
            return False

        compiler = yara_x.Compiler()
        for rf in rule_files:
            try:
                compiler.add_source(rf.read_text(encoding="utf-8", errors="ignore"))
                self._loaded_rule_files.append(rf.name)
            except Exception:
                # A few rules in the public corpus reference modules we may not have;
                # skip silently to keep startup robust.
                continue
        self._scanner = yara_x.Scanner(compiler.build())
        return True

    def match(self, path: Path) -> list[Evidence]:
        if not self._ensure_loaded():
            return [Evidence(
                analyzer="yara", field="status", value="no_rules",
                severity=Severity.INFO,
                description=(
                    "No YARA rules loaded. Run `python scripts/bootstrap_yara.py` to download "
                    "YARA-Forge, or install `yara-x` if missing."
                ),
            )]

        try:
            data = path.read_bytes()
            results = self._scanner.scan(data)
        except Exception as exc:
            return [Evidence(
                analyzer="yara", field="error", value=str(exc)[:200],
                severity=Severity.INFO, description="YARA scan failed",
            )]

        hits = []
        for rule in _iter_matched_rules(results):
            metadata = _extract_metadata(rule)
            hits.append({
                "rule": safe_string(rule.identifier, 120),
                "namespace": safe_string(getattr(rule, "namespace", "default"), 80),
                "tags": list(getattr(rule, "tags", []) or [])[:10],
                "description": safe_string(metadata.get("description", ""), 240),
                "reference": safe_string(metadata.get("reference", ""), 240),
                "author": safe_string(metadata.get("author", ""), 80),
                "score": metadata.get("score"),
            })

        if not hits:
            return [Evidence(
                analyzer="yara", field="match_count", value=0,
                severity=Severity.INFO,
                description=f"No YARA rule hits across {len(self._loaded_rule_files)} loaded rule files",
            )]

        worst = Severity.INFO
        for h in hits:
            sev = _classify_severity(h["rule"], {"score": h.get("score")})
            if _sev_rank(sev) > _sev_rank(worst):
                worst = sev

        return [
            Evidence(
                analyzer="yara", field="match_count", value=len(hits),
                severity=worst,
                description=f"YARA matched {len(hits)} rule(s) — see rule_matches for details",
            ),
            Evidence(
                analyzer="yara", field="rule_matches", value=hits[:50],
                severity=worst,
                description="Individual YARA rule hits with metadata (rule name, tags, reference, author)",
            ),
        ]


def _iter_matched_rules(results) -> Iterable:
    """yara-x has changed API a few times; this normalizes."""
    if hasattr(results, "matching_rules"):
        return results.matching_rules
    return list(results) if results else []


def _extract_metadata(rule) -> dict:
    """yara-x metadata can be a list of (k, v) tuples or dict-like; normalize."""
    out: dict = {}
    md = getattr(rule, "metadata", None) or []
    if isinstance(md, dict):
        return md
    try:
        for entry in md:
            if isinstance(entry, tuple) and len(entry) == 2:
                out[entry[0]] = entry[1]
            elif hasattr(entry, "identifier") and hasattr(entry, "value"):
                out[entry.identifier] = entry.value
    except Exception:
        pass
    return out


def _sev_rank(s: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[s]


YARA_ENGINE = YaraEngine()
