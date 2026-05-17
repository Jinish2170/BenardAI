"""VirusTotal lookups via vt-py (file hash, URL, IP)."""
from __future__ import annotations
import asyncio
import base64
from typing import Any

from ..config import CONFIG
from ..types import Evidence, Severity
from ..analyzers.base import safe_string


def _verdict_severity(malicious: int, suspicious: int) -> Severity:
    if malicious >= 10:
        return Severity.CRITICAL
    if malicious >= 3:
        return Severity.HIGH
    if malicious >= 1 or suspicious >= 3:
        return Severity.MEDIUM
    if suspicious >= 1:
        return Severity.LOW
    return Severity.INFO


def _summarize_stats(stats: dict[str, int]) -> tuple[int, int, int, int]:
    """Returns (malicious, suspicious, harmless, total)."""
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected
    return malicious, suspicious, harmless, total


async def _with_client(coro):
    """Run a vt-py coroutine; gracefully no-op when no key configured."""
    if not CONFIG.intel.vt_api_key:
        return None
    try:
        import vt
    except ImportError:
        return None
    client = vt.Client(CONFIG.intel.vt_api_key)
    try:
        return await coro(client)
    finally:
        await client.close_async()


async def lookup_hash(sha256: str) -> list[Evidence]:
    async def _fetch(client) -> Any:
        return await client.get_object_async(f"/files/{sha256}")

    try:
        obj = await _with_client(_fetch)
    except Exception as exc:
        return [_intel_unavailable("virustotal", f"VT lookup failed: {exc}")]
    if obj is None:
        return [_intel_unavailable("virustotal", "VT_API_KEY not set; skipping VirusTotal hash lookup")]

    stats = obj.last_analysis_stats or {}
    m, s, h, total = _summarize_stats(stats)
    severity = _verdict_severity(m, s)

    names = (obj.names or [])[:5]
    threat_label = getattr(obj, "popular_threat_classification", None) or {}
    suggested_threat = threat_label.get("suggested_threat_label") if isinstance(threat_label, dict) else None
    family = threat_label.get("popular_threat_name", [{}])[0].get("value") if isinstance(threat_label, dict) and threat_label.get("popular_threat_name") else None

    return [
        Evidence(
            analyzer="virustotal", field="detection_ratio", value=f"{m}/{total}",
            severity=severity,
            description=(
                f"VirusTotal: {m} engines flagged this file as malicious "
                f"({s} suspicious, {h} harmless, total {total})"
            ),
            details={"malicious": m, "suspicious": s, "harmless": h, "total": total},
            source_url=f"https://www.virustotal.com/gui/file/{sha256}",
        ),
        Evidence(
            analyzer="virustotal", field="known_filenames",
            value=[safe_string(n, 120) for n in names],
            severity=Severity.INFO,
            description=f"Filenames previously observed for this hash on VirusTotal",
        ),
        Evidence(
            analyzer="virustotal", field="threat_label",
            value=safe_string(suggested_threat or family or "n/a", 120),
            severity=severity if (suggested_threat or family) else Severity.INFO,
            description="Aggregated threat label / family suggested by VirusTotal community",
        ),
    ]


async def lookup_url(url: str) -> list[Evidence]:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def _fetch(client) -> Any:
        return await client.get_object_async(f"/urls/{url_id}")

    try:
        obj = await _with_client(_fetch)
    except Exception as exc:
        return [_intel_unavailable("virustotal", f"VT URL lookup failed: {exc}")]
    if obj is None:
        return [_intel_unavailable("virustotal", "VT_API_KEY not set; skipping VirusTotal URL lookup")]

    stats = obj.last_analysis_stats or {}
    m, s, h, total = _summarize_stats(stats)
    severity = _verdict_severity(m, s)
    return [Evidence(
        analyzer="virustotal", field="url_detection_ratio", value=f"{m}/{total}",
        severity=severity,
        description=f"VirusTotal URL scan: {m}/{total} engines flagged malicious",
        details={"malicious": m, "suspicious": s, "harmless": h, "total": total},
        source_url=f"https://www.virustotal.com/gui/url/{url_id}",
    )]


async def lookup_ip(ip: str) -> list[Evidence]:
    async def _fetch(client) -> Any:
        return await client.get_object_async(f"/ip_addresses/{ip}")

    try:
        obj = await _with_client(_fetch)
    except Exception as exc:
        return [_intel_unavailable("virustotal", f"VT IP lookup failed: {exc}")]
    if obj is None:
        return [_intel_unavailable("virustotal", "VT_API_KEY not set; skipping VirusTotal IP lookup")]

    stats = obj.last_analysis_stats or {}
    m, s, h, total = _summarize_stats(stats)
    severity = _verdict_severity(m, s)
    asn = getattr(obj, "asn", None)
    country = getattr(obj, "country", None)
    return [Evidence(
        analyzer="virustotal", field="ip_detection_ratio", value=f"{m}/{total}",
        severity=severity,
        description=(
            f"VirusTotal IP reputation: {m}/{total} engines flagged "
            f"(ASN {asn}, country {country})"
        ),
        details={"asn": asn, "country": country, "malicious": m, "suspicious": s, "harmless": h, "total": total},
        source_url=f"https://www.virustotal.com/gui/ip-address/{ip}",
    )]


def _intel_unavailable(name: str, msg: str) -> Evidence:
    return Evidence(
        analyzer=name, field="status", value="unavailable",
        severity=Severity.INFO, description=msg,
    )
