"""AbuseIPDB IP reputation lookup."""
from __future__ import annotations
import httpx

from ..config import CONFIG
from ..types import Evidence, Severity
from ..analyzers.base import safe_string

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


async def lookup_ip(ip: str) -> list[Evidence]:
    if not CONFIG.intel.abuseipdb_api_key:
        return [Evidence(
            analyzer="abuseipdb", field="status", value="unavailable",
            severity=Severity.INFO,
            description="ABUSEIPDB_API_KEY not set; skipping AbuseIPDB lookup",
        )]
    headers = {"Key": CONFIG.intel.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    try:
        async with httpx.AsyncClient(timeout=CONFIG.intel.request_timeout_s) as client:
            resp = await client.get(ABUSEIPDB_API, params=params, headers=headers)
            data = resp.json()
    except Exception as exc:
        return [Evidence(
            analyzer="abuseipdb", field="status", value="error",
            severity=Severity.INFO, description=f"AbuseIPDB lookup failed: {exc}",
        )]

    d = data.get("data", {})
    score = int(d.get("abuseConfidenceScore", 0))
    if score >= 75:
        sev = Severity.CRITICAL
    elif score >= 50:
        sev = Severity.HIGH
    elif score >= 25:
        sev = Severity.MEDIUM
    elif score >= 1:
        sev = Severity.LOW
    else:
        sev = Severity.INFO

    return [Evidence(
        analyzer="abuseipdb", field="abuse_confidence", value=score,
        severity=sev,
        description=(
            f"AbuseIPDB confidence-of-abuse: {score}% over last 90 days "
            f"({d.get('totalReports', 0)} reports from {d.get('numDistinctUsers', 0)} users). "
            f"ISP {safe_string(d.get('isp', ''), 80)} · country {d.get('countryCode', '?')}"
        ),
        details={
            "country": d.get("countryCode"),
            "isp": safe_string(d.get("isp", ""), 80),
            "usage_type": safe_string(d.get("usageType", ""), 40),
            "total_reports": d.get("totalReports"),
            "distinct_users": d.get("numDistinctUsers"),
            "last_reported_at": d.get("lastReportedAt"),
        },
        source_url=f"https://www.abuseipdb.com/check/{ip}",
    )]
