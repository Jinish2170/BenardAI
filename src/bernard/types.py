"""Bernard core data model.

All evidence flows as structured objects (never free text fed to the LLM raw)
to defang prompt-injection embedded in malicious samples.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field


# --- Input ---

InputKind = Literal["file", "url", "ip", "domain", "hash"]


class AnalysisInput(BaseModel):
    """Normalized input to the orchestrator."""
    kind: InputKind
    value: str                            # for url/ip/domain/hash: the literal string
    filename: str | None = None           # for file uploads
    file_path: str | None = None          # local path (server-side) for file uploads
    file_sha256: str | None = None        # computed at intake for file uploads


# --- Evidence ---

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """A single piece of structured evidence emitted by an analyzer or intel source.

    Citation contract: the LLM must reference (analyzer, field) when making any
    claim. `value` is the raw datum; `details` may carry richer structured context.
    """
    analyzer: str                          # 'pe', 'pdf', 'yara', 'virustotal', 'urlhaus', ...
    field: str                             # 'imphash', 'rule_match', 'detection_ratio', ...
    value: Any                             # primitive or list/dict
    severity: Severity = Severity.INFO
    description: str = ""                  # human-friendly, but ALSO available to LLM
    details: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None          # link to threat-intel source
    collected_at: datetime = Field(default_factory=datetime.utcnow)


# --- Verdict (LLM output, post-validated) ---

class MitreTechnique(BaseModel):
    technique_id: str                      # e.g. "T1059.001"
    name: str
    rationale: str                         # why the LLM mapped this
    cites: list[str]                       # ["pe.imphash", "yara.rule_match"] — must reference real Evidence


class Verdict(BaseModel):
    classification: Literal["benign", "suspicious", "malicious", "inconclusive"]
    severity: Severity
    confidence: Literal["low", "medium", "high"]
    summary: str                           # 2-4 sentences
    key_indicators: list[str]              # bullet points, each MUST end with [analyzer.field] citation
    mitre_techniques: list[MitreTechnique]
    recommended_actions: list[str]
    abstention_reason: str | None = None   # populated when classification == "inconclusive"


# --- Full record ---

class AnalysisRecord(BaseModel):
    id: str
    input: AnalysisInput
    evidence: list[Evidence]
    verdict: Verdict
    stats: dict[str, Any]                  # duration, analyzers_run, llm_model, ...
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AnalysisSummary(BaseModel):
    id: str
    kind: InputKind
    value: str
    classification: str
    severity: Severity
    created_at: datetime
    evidence_count: int


# --- Progress events (for streaming) ---

class ProgressEvent(BaseModel):
    phase: Literal["intake", "analyze", "enrich", "triage", "done", "error", "warning"]
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
