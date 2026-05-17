"""Download and unpack the YARA-Forge `core` ruleset into rules/yara-forge/.

YARA-Forge bundles a curated, auto-quality-checked set of YARA rules aggregated
from ~70 public sources (Florian Roth's signature-base, Elastic, ReversingLabs,
…). The `core` package is the conservative tier — fewer false positives.

Run: python scripts/bootstrap_yara.py
"""
from __future__ import annotations
import io
import sys
import zipfile
from pathlib import Path
import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "yara-forge"

# Latest release endpoint always points to the newest packaging
YARA_FORGE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"


def main() -> int:
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[bootstrap_yara] querying YARA-Forge latest release …")
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        meta = client.get(YARA_FORGE_API).json()
        # Pick the `yara-forge-rules-core.zip` asset (conservative ruleset)
        asset = next(
            (a for a in meta.get("assets", []) if "core" in a["name"].lower() and a["name"].endswith(".zip")),
            None,
        )
        if not asset:
            print("[bootstrap_yara] could not find a 'core' zip in latest release.", file=sys.stderr)
            print(f"  Assets available: {[a['name'] for a in meta.get('assets', [])]}")
            return 1
        print(f"[bootstrap_yara] downloading {asset['name']} ({asset['size']} bytes)")
        data = client.get(asset["browser_download_url"]).content

    print(f"[bootstrap_yara] unpacking into {RULES_DIR}")
    extracted = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith((".yar", ".yara")):
                continue
            target = RULES_DIR / Path(info.filename).name
            target.write_bytes(zf.read(info))
            extracted += 1
    print(f"[bootstrap_yara] OK — {extracted} rule files written to {RULES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
