"""Generic file analyzer: hashes, size, entropy, printable strings, magic type."""
from __future__ import annotations
import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from ...types import Evidence, Severity
from ..base import FileAnalyzer, safe_list, safe_string

_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")

# Heuristics for suspicious tokens in strings
_SUSPICIOUS_TOKENS = [
    "powershell",
    "cmd.exe",
    "regsvr32",
    "mshta",
    "rundll32",
    "schtasks",
    "wmic",
    "vssadmin",
    "bcdedit",
    "Invoke-Expression",
    "DownloadString",
    "FromBase64String",
    "WScript.Shell",
    "Shell.Application",
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "SetWindowsHookEx",
    "LoadLibrary",
    "GetProcAddress",
    "/c \"",
    "AAAA",  # potential PE header in base64
]

# Likely IOCs
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_IPV4_RE = re.compile(rb"\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class GenericFileAnalyzer(FileAnalyzer):
    name = "generic"

    def supports(self, path: Path, magic_type: str) -> bool:
        return True

    def analyze(self, path: Path) -> list[Evidence]:
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        size = len(data)
        entropy = round(_entropy(data), 3)

        # Detect significant string content
        printable = _PRINTABLE.findall(data)
        printable_strings = [s.decode("ascii", errors="replace") for s in printable]

        suspicious_hits = []
        joined_lower = b"\n".join(printable).lower()
        for token in _SUSPICIOUS_TOKENS:
            if token.lower().encode() in joined_lower:
                suspicious_hits.append(token)

        urls = list({m.decode("ascii", errors="replace") for m in _URL_RE.findall(data)})
        ips = list({m.decode("ascii", errors="replace") for m in _IPV4_RE.findall(data)})

        ev: list[Evidence] = [
            Evidence(
                analyzer=self.name,
                field="sha256",
                value=sha256,
                severity=Severity.INFO,
                description="SHA-256 of the sample",
            ),
            Evidence(
                analyzer=self.name,
                field="md5",
                value=md5,
                severity=Severity.INFO,
                description="MD5 of the sample",
            ),
            Evidence(
                analyzer=self.name,
                field="sha1",
                value=sha1,
                severity=Severity.INFO,
                description="SHA-1 of the sample",
            ),
            Evidence(
                analyzer=self.name,
                field="size_bytes",
                value=size,
                severity=Severity.INFO,
                description=f"File size: {size} bytes",
            ),
            Evidence(
                analyzer=self.name,
                field="entropy",
                value=entropy,
                severity=Severity.MEDIUM if entropy > 7.2 else Severity.INFO,
                description=(
                    f"Shannon entropy {entropy} (>7.2 typically indicates packing/encryption)"
                    if entropy > 7.2
                    else f"Shannon entropy {entropy}"
                ),
            ),
            Evidence(
                analyzer=self.name,
                field="printable_string_count",
                value=len(printable_strings),
                severity=Severity.INFO,
                description=f"Extracted {len(printable_strings)} printable strings (>=6 chars)",
            ),
        ]

        if suspicious_hits:
            ev.append(
                Evidence(
                    analyzer=self.name,
                    field="suspicious_tokens",
                    value=safe_list(suspicious_hits, max_items=30, max_len=80),
                    severity=Severity.HIGH if len(suspicious_hits) >= 3 else Severity.MEDIUM,
                    description=(
                        f"Found {len(suspicious_hits)} tokens commonly associated with malicious "
                        "execution patterns (process spawning, in-memory loading, persistence, etc.)"
                    ),
                )
            )

        if urls:
            ev.append(
                Evidence(
                    analyzer=self.name,
                    field="embedded_urls",
                    value=safe_list(urls, max_items=20, max_len=200),
                    severity=Severity.MEDIUM if urls else Severity.INFO,
                    description=f"Sample contains {len(urls)} embedded URL(s); see intel checks below",
                )
            )

        if ips:
            ev.append(
                Evidence(
                    analyzer=self.name,
                    field="embedded_ips",
                    value=safe_list(ips, max_items=20, max_len=15),
                    severity=Severity.MEDIUM,
                    description=f"Sample contains {len(ips)} embedded IPv4 address(es)",
                )
            )

        # Notable strings preview for the LLM (sanitized)
        notable = [s for s in printable_strings if len(s) >= 12][:25]
        if notable:
            ev.append(
                Evidence(
                    analyzer=self.name,
                    field="notable_strings",
                    value=safe_list(notable, max_items=25, max_len=120),
                    severity=Severity.INFO,
                    description="Sample of long printable strings (sanitized; for LLM context)",
                )
            )

        return ev
