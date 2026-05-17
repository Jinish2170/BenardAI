"""File-based analysis persistence."""
from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path

from .config import CONFIG
from .types import AnalysisRecord, AnalysisSummary, Severity, InputKind


def _sanitize(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s)[:60]


def _date_dir(d: datetime) -> str:
    return d.strftime("%Y-%m-%d")


class AnalysisStore:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else CONFIG.storage.analyses_dir
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, record: AnalysisRecord) -> str:
        day_dir = self.root / _date_dir(record.created_at)
        day_dir.mkdir(parents=True, exist_ok=True)
        slug = _sanitize(record.input.value or record.input.filename or "analysis")
        path = day_dir / f"{slug}__{record.id}.json"
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
        return str(path.relative_to(self.root))

    def list(self, limit: int = 100) -> list[AnalysisSummary]:
        if not self.root.exists():
            return []
        out: list[AnalysisSummary] = []
        for day in sorted(self.root.iterdir(), reverse=True):
            if not day.is_dir():
                continue
            for f in sorted(day.iterdir(), reverse=True):
                if not f.suffix == ".json":
                    continue
                try:
                    raw = json.loads(f.read_text(encoding="utf-8"))
                    rec = AnalysisRecord.model_validate(raw)
                    out.append(AnalysisSummary(
                        id=rec.id,
                        kind=rec.input.kind,
                        value=rec.input.value or rec.input.filename or "",
                        classification=rec.verdict.classification,
                        severity=rec.verdict.severity,
                        created_at=rec.created_at,
                        evidence_count=len(rec.evidence),
                    ))
                    if len(out) >= limit:
                        return out
                except Exception:
                    continue
        return out

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        if not self.root.exists():
            return None
        for day in self.root.iterdir():
            if not day.is_dir():
                continue
            for f in day.iterdir():
                if analysis_id in f.name and f.suffix == ".json":
                    try:
                        return AnalysisRecord.model_validate_json(f.read_text(encoding="utf-8"))
                    except Exception:
                        return None
        return None


STORE = AnalysisStore()
