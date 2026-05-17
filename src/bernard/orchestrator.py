"""Bernard orchestrator — routes an AnalysisInput through analyzers + intel + triage."""
from __future__ import annotations
import asyncio
import hashlib
import re
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Callable

from .analyzers.file import ALL_FILE_ANALYZERS
from .analyzers.yara_engine import YARA_ENGINE
from .intel import (
    abuseipdb_lookup_ip,
    bazaar_lookup_hash,
    threatfox_lookup,
    urlhaus_lookup_url,
    vt_lookup_hash,
    vt_lookup_ip,
    vt_lookup_url,
)
from .store import STORE
from .triage import synthesize_verdict
from .triage.llm import get_model
from .types import AnalysisInput, AnalysisRecord, Evidence, InputKind, ProgressEvent


ProgressCallback = Callable[[ProgressEvent], None] | None


# ---------- Input detection ----------

_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_kind(value: str) -> InputKind:
    v = value.strip()
    if _SHA256_RE.match(v) or _SHA1_RE.match(v) or _MD5_RE.match(v):
        return "hash"
    if _URL_RE.match(v):
        return "url"
    if _IPV4_RE.match(v):
        return "ip"
    if _DOMAIN_RE.match(v):
        return "domain"
    raise ValueError(
        f"Could not classify '{v[:80]}'. Bernard accepts file uploads, URLs, IPs, domains, "
        "and MD5/SHA1/SHA256 hashes."
    )


# ---------- Magic detection (graceful when libmagic unavailable) ----------

def _magic_type(path: Path) -> str:
    try:
        import magic  # type: ignore
        return magic.from_file(str(path))
    except Exception:
        return ""


# ---------- File pipeline ----------

async def _analyze_file(path: Path, emit: ProgressCallback) -> list[Evidence]:
    evidence: list[Evidence] = []
    magic_type = _magic_type(path)
    if magic_type:
        evidence.append(Evidence(
            analyzer="meta", field="magic_type", value=magic_type,
            description=f"File type detected by libmagic: {magic_type}",
        ))

    for analyzer in ALL_FILE_ANALYZERS:
        if not analyzer.supports(path, magic_type):
            continue
        _emit(emit, "analyze", f"Running {analyzer.name} analyzer")
        try:
            ev = await asyncio.to_thread(analyzer.analyze, path)
            evidence.extend(ev)
        except Exception as exc:
            evidence.append(Evidence(
                analyzer=analyzer.name, field="error", value=str(exc)[:200],
                description=f"{analyzer.name} analyzer raised: {exc}",
            ))

    _emit(emit, "analyze", "Running YARA-X scan")
    yara_ev = await asyncio.to_thread(YARA_ENGINE.match, path)
    evidence.extend(yara_ev)
    return evidence


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- Intel pipeline (per input kind) ----------

async def _enrich_file(sha256: str, embedded_urls: list[str], embedded_ips: list[str],
                       emit: ProgressCallback) -> list[Evidence]:
    tasks = [
        vt_lookup_hash(sha256),
        bazaar_lookup_hash(sha256),
        threatfox_lookup(sha256),
    ]
    for u in embedded_urls[:3]:        # cap to avoid abuse-of-free-tier
        tasks.append(urlhaus_lookup_url(u))
    for ip in embedded_ips[:3]:
        tasks.append(vt_lookup_ip(ip))
        tasks.append(abuseipdb_lookup_ip(ip))

    _emit(emit, "enrich", f"Enriching with {len(tasks)} threat-intel sources (hash, IOCs)")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[Evidence] = []
    for r in results:
        if isinstance(r, Exception):
            out.append(Evidence(analyzer="intel", field="error", value=str(r)[:200]))
        elif r:
            out.extend(r)
    return out


async def _enrich_url(url: str, emit: ProgressCallback) -> list[Evidence]:
    _emit(emit, "enrich", "Enriching URL with URLhaus + VirusTotal + ThreatFox")
    results = await asyncio.gather(
        urlhaus_lookup_url(url),
        vt_lookup_url(url),
        threatfox_lookup(url),
        return_exceptions=True,
    )
    out: list[Evidence] = []
    for r in results:
        if isinstance(r, Exception):
            out.append(Evidence(analyzer="intel", field="error", value=str(r)[:200]))
        elif r:
            out.extend(r)
    return out


async def _enrich_ip(ip: str, emit: ProgressCallback) -> list[Evidence]:
    _emit(emit, "enrich", "Enriching IP with VirusTotal + AbuseIPDB + ThreatFox")
    results = await asyncio.gather(
        vt_lookup_ip(ip),
        abuseipdb_lookup_ip(ip),
        threatfox_lookup(ip),
        return_exceptions=True,
    )
    out: list[Evidence] = []
    for r in results:
        if isinstance(r, Exception):
            out.append(Evidence(analyzer="intel", field="error", value=str(r)[:200]))
        elif r:
            out.extend(r)
    return out


async def _enrich_hash(h: str, emit: ProgressCallback) -> list[Evidence]:
    _emit(emit, "enrich", "Enriching hash with VirusTotal + MalwareBazaar + ThreatFox")
    results = await asyncio.gather(
        vt_lookup_hash(h),
        bazaar_lookup_hash(h),
        threatfox_lookup(h),
        return_exceptions=True,
    )
    out: list[Evidence] = []
    for r in results:
        if isinstance(r, Exception):
            out.append(Evidence(analyzer="intel", field="error", value=str(r)[:200]))
        elif r:
            out.extend(r)
    return out


# ---------- Helpers ----------

def _emit(cb: ProgressCallback, phase: str, message: str, **detail) -> None:
    if cb:
        cb(ProgressEvent(phase=phase, message=message, detail=detail))


def _input_summary(inp: AnalysisInput) -> str:
    if inp.kind == "file":
        return f"FILE upload: {inp.filename or '(unnamed)'} (sha256: {inp.file_sha256 or '?'})"
    return f"{inp.kind.upper()}: {inp.value}"


def _extract_embedded(evidence: list[Evidence], field: str) -> list[str]:
    for e in evidence:
        if e.analyzer == "generic" and e.field == field and isinstance(e.value, list):
            return [str(v) for v in e.value]
    return []


# ---------- Public API ----------

async def analyze(inp: AnalysisInput, emit: ProgressCallback = None) -> AnalysisRecord:
    """Run the full pipeline: analyzers -> intel -> LLM triage -> AnalysisRecord."""
    started = time.time()
    analysis_id = f"ana-{int(started * 1000)}-{uuid.uuid4().hex[:6]}"
    evidence: list[Evidence] = []

    _emit(emit, "intake", f"Bernard analyzing {inp.kind}: {inp.value or inp.filename or '?'}")

    if inp.kind == "file":
        if not inp.file_path:
            raise ValueError("file input requires a server-side file_path")
        path = Path(inp.file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not inp.file_sha256:
            inp = inp.model_copy(update={"file_sha256": _sha256_of(path)})

        file_ev = await _analyze_file(path, emit)
        evidence.extend(file_ev)

        embedded_urls = _extract_embedded(file_ev, "embedded_urls")
        embedded_ips = _extract_embedded(file_ev, "embedded_ips")
        intel_ev = await _enrich_file(inp.file_sha256, embedded_urls, embedded_ips, emit)
        evidence.extend(intel_ev)

    elif inp.kind == "url":
        evidence.extend(await _enrich_url(inp.value, emit))
    elif inp.kind == "ip":
        evidence.extend(await _enrich_ip(inp.value, emit))
    elif inp.kind == "domain":
        # Reuse URL pipeline (URLhaus / ThreatFox both handle domains)
        evidence.extend(await _enrich_url(f"http://{inp.value}", emit))
        evidence.extend(await threatfox_lookup(inp.value))
    elif inp.kind == "hash":
        evidence.extend(await _enrich_hash(inp.value, emit))
    else:
        raise ValueError(f"Unsupported input kind: {inp.kind}")

    _emit(emit, "triage", f"Synthesizing verdict with {get_model()}")
    verdict = await synthesize_verdict(input_summary=_input_summary(inp), evidence=evidence)

    duration_ms = int((time.time() - started) * 1000)
    record = AnalysisRecord(
        id=analysis_id,
        input=inp,
        evidence=evidence,
        verdict=verdict,
        stats={
            "duration_ms": duration_ms,
            "evidence_count": len(evidence),
            "analyzers_run": sorted({e.analyzer for e in evidence}),
            "llm_model": get_model(),
        },
    )

    try:
        rel = STORE.save(record)
        _emit(emit, "done", f"Analysis complete in {duration_ms}ms — saved {rel}")
    except Exception as exc:
        _emit(emit, "warning", f"Could not persist analysis: {exc}")

    return record
