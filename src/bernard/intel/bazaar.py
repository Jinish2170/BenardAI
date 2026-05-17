"""MalwareBazaar (abuse.ch) hash lookup — free, no key required."""
from __future__ import annotations
import httpx

from ..config import CONFIG
from ..types import Evidence, Severity
from ..analyzers.base import safe_string

BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


async def lookup_hash(sha256: str) -> list[Evidence]:
    headers = {}
    if CONFIG.intel.abusech_api_key:
        headers["Auth-Key"] = CONFIG.intel.abusech_api_key
    payload = {"query": "get_info", "hash": sha256}
    try:
        async with httpx.AsyncClient(timeout=CONFIG.intel.request_timeout_s) as client:
            resp = await client.post(BAZAAR_API, data=payload, headers=headers)
            if resp.status_code == 401:
                return [Evidence(
                    analyzer="malwarebazaar", field="auth_required", value=True,
                    severity=Severity.INFO,
                    description=(
                        "MalwareBazaar now requires a free auth key. Register at "
                        "https://auth.abuse.ch/ and set ABUSECH_API_KEY in .env to enable MalwareBazaar lookups."
                    ),
                )]
            data = resp.json()
    except Exception as exc:
        return [Evidence(
            analyzer="malwarebazaar", field="status", value="error",
            severity=Severity.INFO, description=f"MalwareBazaar lookup failed: {exc}",
        )]

    if data.get("query_status") != "ok" or not data.get("data"):
        return [Evidence(
            analyzer="malwarebazaar", field="query_status",
            value=safe_string(data.get("query_status", "no_results"), 40),
            severity=Severity.INFO,
            description="No MalwareBazaar entries for this hash",
        )]

    item = data["data"][0]
    sig = safe_string(item.get("signature", ""), 80)
    tags = [safe_string(t, 40) for t in (item.get("tags") or [])][:12]
    first_seen = safe_string(item.get("first_seen", ""), 30)
    file_type = safe_string(item.get("file_type", ""), 30)

    return [Evidence(
        analyzer="malwarebazaar", field="match", value=True,
        severity=Severity.CRITICAL,
        description=(
            f"Sample is in MalwareBazaar's corpus — confirmed malicious. "
            f"Family/signature: {sig or 'unattributed'}; type {file_type}; first seen {first_seen}."
        ),
        details={"signature": sig, "tags": tags, "first_seen": first_seen, "file_type": file_type},
        source_url=f"https://bazaar.abuse.ch/sample/{sha256}/",
    )]
