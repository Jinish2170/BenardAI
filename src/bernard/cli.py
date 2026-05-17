"""Bernard CLI entry."""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path

from .orchestrator import analyze, detect_kind
from .types import AnalysisInput


def _make_input(args) -> AnalysisInput:
    if args.file:
        path = Path(args.file).resolve()
        if not path.exists():
            print(f"error: file not found: {path}", file=sys.stderr)
            sys.exit(2)
        return AnalysisInput(kind="file", value=path.name, filename=path.name, file_path=str(path))
    return AnalysisInput(kind=detect_kind(args.value), value=args.value)


def main() -> None:
    p = argparse.ArgumentParser(prog="bernard", description="Bernard — AI threat triage")
    sub = p.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run the FastAPI server")
    serve.add_argument("--port", type=int, default=None)

    scan = sub.add_parser("scan", help="Analyze a file, URL, IP, domain, or hash")
    group = scan.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Path to a sample file")
    group.add_argument("--value", type=str, help="URL / IP / domain / hash to analyze")
    scan.add_argument("--json", action="store_true", help="Emit raw JSON instead of human-readable output")

    args = p.parse_args()

    if args.cmd == "serve":
        from .api.server import main as serve_main
        if args.port:
            import os
            os.environ["PORT"] = str(args.port)
        serve_main()
        return

    if args.cmd == "scan":
        inp = _make_input(args)
        print(f"[bernard] analyzing {inp.kind}: {inp.value}", file=sys.stderr)

        def emit(ev):
            print(f"  [{ev.phase}] {ev.message}", file=sys.stderr)

        record = asyncio.run(analyze(inp, emit=emit))

        if args.json:
            print(record.model_dump_json(indent=2))
        else:
            v = record.verdict
            print(f"\n=== Bernard verdict ===")
            print(f"Classification: {v.classification.upper()}  ·  Severity: {v.severity.value}  ·  Confidence: {v.confidence}")
            print(f"\nSummary:\n{v.summary}")
            if v.key_indicators:
                print(f"\nKey indicators:")
                for ind in v.key_indicators:
                    print(f"  - {ind}")
            if v.mitre_techniques:
                print(f"\nMITRE ATT&CK techniques:")
                for t in v.mitre_techniques:
                    print(f"  - {t.technique_id} {t.name}  (cites: {', '.join(t.cites)})")
                    print(f"      {t.rationale}")
            if v.recommended_actions:
                print(f"\nRecommended actions:")
                for a in v.recommended_actions:
                    print(f"  - {a}")
            print(f"\n({record.stats['evidence_count']} evidence items · {record.stats['duration_ms']}ms · {record.stats['llm_model']})")


if __name__ == "__main__":
    main()
