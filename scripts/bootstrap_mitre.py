"""Download MITRE ATT&CK enterprise STIX bundle into data/mitre-attack-stix/.

Source: https://github.com/mitre-attack/attack-stix-data (official, MIT)
"""
from __future__ import annotations
import sys
from pathlib import Path
import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = REPO_ROOT / "data" / "mitre-attack-stix"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def main() -> int:
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[bootstrap_mitre] downloading {STIX_URL}")
    try:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            r = client.get(STIX_URL)
            r.raise_for_status()
            (TARGET_DIR / "enterprise-attack.json").write_bytes(r.content)
    except Exception as exc:
        print(f"[bootstrap_mitre] FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"[bootstrap_mitre] OK — saved enterprise-attack.json ({(TARGET_DIR / 'enterprise-attack.json').stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
