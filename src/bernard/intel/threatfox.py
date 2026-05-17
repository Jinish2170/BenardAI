"""ThreatFox (abuse.ch) IOC lookup — free, no key required for public API."""
from __future__ import annotations
import httpx

from ..config import CONFIG
from ..types import Evidence, Severity
from ..analyzers.base import safe_string

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


async def lookup_ioc(ioc: str) -> list[Evidence]:
    """ThreatFox accepts hashes, URLs, IPs, and domains in one search endpoint."""
    headers = {}
    if CONFIG.intel.abusech_api_key:
        headers["Auth-Key"] = CONFIG.intel.abusech_api_key
    payload = {"query": "search_ioc", "search_term": ioc}
    try:
        async with httpx.AsyncClient(timeout=CONFIG.intel.request_timeout_s) as client:
            resp = await client.post(THREATFOX_API, json=payload, headers=headers)
            if resp.status_code == 401:
                return [Evidence(
                    analyzer="threatfox", field="auth_required", value=True,
                    severity=Severity.INFO,
                    description=(
                        "ThreatFox now requires a free auth key. Register at "
                        "https://auth.abuse.ch/ and set ABUSECH_API_KEY in .env to enable ThreatFox lookups."
                    ),
                )]
            data = resp.json()
    except Exception as exc:
        return [Evidence(
            analyzer="threatfox", field="status", value="error",
            severity=Severity.INFO, description=f"ThreatFox lookup failed: {exc}",
        )]

    if data.get("query_status") != "ok":
        return [Evidence(
            analyzer="threatfox", field="query_status",
            value=safe_string(data.get("query_status", "unknown"), 40),
            severity=Severity.INFO,
            description="ThreatFox has no matching IOC entries",
        )]

    items = data.get("data", []) or []
    summary = []
    for it in items[:10]:
        summary.append({
            "malware": safe_string(it.get("malware_printable", ""), 80),
            "threat_type": safe_string(it.get("threat_type_desc", ""), 80),
            "confidence_level": it.get("confidence_level"),
            "first_seen": safe_string(it.get("first_seen", ""), 30),
            "tags": [safe_string(t, 40) for t in (it.get("tags") or [])][:8],
        })
    worst_conf = max((s.get("confidence_level") or 0 for s in summary), default=0)
    sev = Severity.CRITICAL if worst_conf >= 75 else Severity.HIGH if worst_conf >= 50 else Severity.MEDIUM
    return [Evidence(
        analyzer="threatfox", field="ioc_matches", value=summary,
        severity=sev,
        description=(
            f"ThreatFox has {len(items)} entries for this IOC "
            f"(highest confidence {worst_conf}%). Active C2/distribution infrastructure."
        ),
    )]
