"""LLM triage engine: turns evidence into a validated verdict."""
from __future__ import annotations
import json
import re
from typing import Any

from ..intel.mitre import MITRE
from ..types import Evidence, MitreTechnique, Severity, Verdict
from .llm import chat
from .prompts import SYSTEM_PROMPT, build_user_prompt


_CITATION_RE = re.compile(r"\[([a-z][a-z0-9_]*)\.([a-z0-9_]+)\]")


async def synthesize_verdict(*, input_summary: str, evidence: list[Evidence]) -> Verdict:
    """Run the LLM, parse + validate the JSON response into a typed Verdict."""
    mitre_ref = MITRE.fmt_for_prompt() if MITRE.is_loaded() else ""
    user_prompt = build_user_prompt(
        input_summary=input_summary,
        evidence=evidence,
        mitre_reference=mitre_ref,
    )

    raw = await chat(system=SYSTEM_PROMPT, user=user_prompt, json_mode=True, temperature=0.15)
    parsed = _parse_json(raw)
    return _validate(parsed, evidence)


def _parse_json(raw: str) -> dict:
    text = raw.strip()
    # Strip any accidental code fences
    fence = re.match(r"^```(?:json)?\s*(\{[\s\S]*\})\s*```$", text, re.MULTILINE)
    if fence:
        text = fence.group(1)
    # Or trim to outermost braces
    first, last = text.find("{"), text.rfind("}")
    if first >= 0 and last > first:
        text = text[first : last + 1]
    try:
        return json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"LLM did not return valid JSON: {exc}\nRaw: {raw[:400]}")


def _allowed_citations(evidence: list[Evidence]) -> set[str]:
    return {f"{e.analyzer}.{e.field}" for e in evidence}


def _validate(parsed: dict, evidence: list[Evidence]) -> Verdict:
    """Validate the LLM output. Drops hallucinated citations and unknown MITRE IDs."""
    allowed = _allowed_citations(evidence)

    # --- Key indicators: keep only the ones that carry a valid citation
    cleaned_indicators: list[str] = []
    for ind in (parsed.get("key_indicators") or []):
        text = str(ind).strip()
        cits = _CITATION_RE.findall(text)
        if not cits:
            continue
        if all(f"{a}.{f}" in allowed for (a, f) in cits):
            cleaned_indicators.append(text)
        # silently drop indicators with hallucinated citations

    # --- MITRE techniques: drop unknown IDs and orphaned citations
    cleaned_techniques: list[MitreTechnique] = []
    for tech in (parsed.get("mitre_techniques") or []):
        tid = str(tech.get("technique_id", "")).strip()
        if not tid:
            continue
        if MITRE.is_loaded() and not MITRE.known(tid):
            continue
        cites = [c for c in (tech.get("cites") or []) if c in allowed]
        if not cites:
            continue
        meta = MITRE.get(tid) if MITRE.is_loaded() else None
        cleaned_techniques.append(MitreTechnique(
            technique_id=tid,
            name=str(tech.get("name") or (meta.get("name") if meta else "")).strip(),
            rationale=str(tech.get("rationale", "")).strip()[:600],
            cites=cites,
        ))

    classification = parsed.get("classification", "inconclusive")
    if classification not in ("benign", "suspicious", "malicious", "inconclusive"):
        classification = "inconclusive"

    severity_raw = parsed.get("severity", "info").lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.INFO

    confidence = parsed.get("confidence", "low")
    if confidence not in ("low", "medium", "high"):
        confidence = "low"

    abstention_reason: str | None = None
    if classification == "inconclusive":
        abstention_reason = parsed.get("abstention_reason") or "LLM abstained without giving a reason"

    return Verdict(
        classification=classification,
        severity=severity,
        confidence=confidence,
        summary=str(parsed.get("summary", "")).strip(),
        key_indicators=cleaned_indicators,
        mitre_techniques=cleaned_techniques,
        recommended_actions=[
            str(a).strip() for a in (parsed.get("recommended_actions") or []) if str(a).strip()
        ][:10],
        abstention_reason=abstention_reason,
    )
