"""URLhaus (abuse.ch) URL lookup — free, no key required for public API."""
from __future__ import annotations
import httpx

from ..config import CONFIG
from ..types import Evidence, Severity
from ..analyzers.base import safe_string


URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


async def lookup_url(url: str) -> list[Evidence]:
    headers = {}
    if CONFIG.intel.abusech_api_key:
        headers["Auth-Key"] = CONFIG.intel.abusech_api_key
    try:
        async with httpx.AsyncClient(timeout=CONFIG.intel.request_timeout_s) as client:
            resp = await client.post(URLHAUS_API, data={"url": url}, headers=headers)
            if resp.status_code == 401:
                return [Evidence(
                    analyzer="urlhaus", field="auth_required", value=True,
                    severity=Severity.INFO,
                    description=(
                        "URLhaus now requires a free auth key. Register at "
                        "https://auth.abuse.ch/ and set ABUSECH_API_KEY in .env to enable URLhaus lookups."
                    ),
                )]
            data = resp.json()
    except Exception as exc:
        return [Evidence(
            analyzer="urlhaus", field="status", value="error",
            severity=Severity.INFO, description=f"URLhaus lookup failed: {exc}",
        )]

    status = data.get("query_status", "unknown")
    if status == "no_results":
        return [Evidence(
            analyzer="urlhaus", field="query_status", value="no_results",
            severity=Severity.INFO, description="URLhaus has no entry for this URL",
        )]
    if status != "ok":
        return [Evidence(
            analyzer="urlhaus", field="query_status", value=safe_string(status, 60),
            severity=Severity.INFO, description=f"URLhaus query status: {status}",
        )]

    threat = safe_string(data.get("threat", "malware_download"), 60)
    payload = data.get("payloads") or []
    payloads_summary = []
    for p in payload[:5]:
        payloads_summary.append({
            "filename": safe_string(p.get("filename", ""), 120),
            "file_type": safe_string(p.get("file_type", ""), 30),
            "signature": safe_string(p.get("signature", ""), 120),
            "sha256": safe_string(p.get("response_sha256", ""), 64),
        })
    tags = (data.get("tags") or [])[:10]
    date_added = safe_string(data.get("date_added", ""), 30)

    ev = [Evidence(
        analyzer="urlhaus", field="listed", value=True,
        severity=Severity.CRITICAL,
        description=(
            f"URL listed on URLhaus as {threat} (added {date_added}). "
            f"abuse.ch is high-confidence: a listing here is essentially a confirmed malicious URL."
        ),
        details={"threat": threat, "tags": tags, "date_added": date_added},
        source_url=safe_string(data.get("urlhaus_reference", ""), 240) or None,
    )]
    if payloads_summary:
        ev.append(Evidence(
            analyzer="urlhaus", field="payloads", value=payloads_summary,
            severity=Severity.HIGH,
            description=f"{len(payloads_summary)} payload(s) historically served from this URL",
        ))
    return ev
