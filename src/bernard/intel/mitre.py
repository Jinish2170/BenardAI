"""MITRE ATT&CK technique catalog (loaded from STIX JSON).

Used by the LLM triage layer to validate that any technique IDs the model
claims to have mapped actually exist (rejects orphaned/hallucinated IDs).
"""
from __future__ import annotations
import json
import re
from functools import lru_cache
from pathlib import Path

from ..config import CONFIG

# STIX bundle filename inside data/mitre-attack-stix/
ENTERPRISE_STIX = "enterprise-attack.json"


@lru_cache(maxsize=1)
def _load_techniques() -> dict[str, dict]:
    path = CONFIG.storage.mitre_dir / ENTERPRISE_STIX
    if not path.exists():
        return {}
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references") or []
        tid = next((r.get("external_id") for r in ext_refs
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tactics = []
        for k in obj.get("kill_chain_phases") or []:
            phase = k.get("phase_name")
            if phase:
                tactics.append(phase)
        out[tid] = {
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "")[:600],
            "tactics": tactics,
            "url": next((r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"), None),
        }
    return out


class MitreCatalog:
    """Validates technique IDs and provides human-friendly metadata."""

    def __init__(self) -> None:
        self._techniques = _load_techniques()

    def is_loaded(self) -> bool:
        return bool(self._techniques)

    def known(self, technique_id: str) -> bool:
        return technique_id in self._techniques

    def get(self, technique_id: str) -> dict | None:
        return self._techniques.get(technique_id)

    def filter_known(self, technique_ids: list[str]) -> tuple[list[str], list[str]]:
        """Returns (known, unknown) lists."""
        known, unknown = [], []
        for t in technique_ids:
            (known if t in self._techniques else unknown).append(t)
        return known, unknown

    def fmt_for_prompt(self, max_techniques: int = 40) -> str:
        """A compact reference snippet the LLM can use to ground technique claims.

        We don't dump the whole 700-technique catalog; we curate the most
        triage-relevant ones (initial access, execution, persistence, defense
        evasion, C2, exfil) so the LLM has hooks without context-bloat.
        """
        priority_prefixes = re.compile(r"^T(105[6-9]|10[0-4]\d|1027|1036|1055|1059|1071|1547|1574|1041|1567|1486|1497)")
        picks = [(tid, meta) for tid, meta in self._techniques.items()
                 if priority_prefixes.match(tid)]
        picks = picks[:max_techniques]
        lines = []
        for tid, meta in picks:
            tactics = ",".join(meta.get("tactics", [])[:3])
            lines.append(f"{tid} | {meta['name']} | tactics: {tactics or 'n/a'}")
        return "\n".join(lines)


MITRE = MitreCatalog()
