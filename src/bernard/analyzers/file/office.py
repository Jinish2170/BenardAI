"""Office document analyzer using oletools (olevba + oleid)."""
from __future__ import annotations
from pathlib import Path

from ...types import Evidence, Severity
from ..base import FileAnalyzer, safe_list, safe_string

_OFFICE_EXTS = {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlt",
                ".xltm", ".ppt", ".pptm", ".pot", ".potm", ".odt", ".ods", ".odp", ".rtf"}


class OfficeAnalyzer(FileAnalyzer):
    name = "office"

    def supports(self, path: Path, magic_type: str) -> bool:
        if path.suffix.lower() in _OFFICE_EXTS:
            return True
        if "Composite Document File" in magic_type or "Microsoft" in magic_type:
            return True
        # OLE2 / Zip magic for old + new Office
        try:
            with open(path, "rb") as fh:
                head = fh.read(8)
            if head[:4] == b"\xd0\xcf\x11\xe0":   # OLE2
                return True
            if head[:2] == b"PK":                  # could be OOXML zip
                return path.suffix.lower() in _OFFICE_EXTS
        except OSError:
            return False
        return False

    def analyze(self, path: Path) -> list[Evidence]:
        try:
            from oletools.olevba import VBA_Parser
        except ImportError:
            return [Evidence(
                analyzer=self.name, field="error", value="oletools not installed",
                severity=Severity.INFO, description="oletools missing; skipping Office analysis",
            )]

        ev: list[Evidence] = []
        try:
            vp = VBA_Parser(str(path))
        except Exception as exc:
            return [Evidence(
                analyzer=self.name, field="parse_error", value=str(exc)[:200],
                severity=Severity.LOW, description="oletools could not parse this Office file",
            )]

        try:
            if not vp.detect_vba_macros():
                ev.append(Evidence(
                    analyzer=self.name, field="vba_macros", value=False,
                    severity=Severity.INFO, description="No VBA macros detected",
                ))
                return ev

            ev.append(Evidence(
                analyzer=self.name, field="vba_macros", value=True,
                severity=Severity.MEDIUM,
                description="VBA macros present (presence alone is not malicious; see analysis below)",
            ))

            # Collect macro source for keyword analysis
            macro_strs = []
            for (_filename, _stream, _vba_filename, vba_code) in vp.extract_macros():
                if vba_code:
                    macro_strs.append(vba_code)
            joined = "\n".join(macro_strs)
            preview = safe_string(joined[:800], max_len=800)
            ev.append(Evidence(
                analyzer=self.name, field="macro_preview", value=preview,
                severity=Severity.INFO,
                description=f"Sanitized preview of extracted VBA (full size {len(joined)} chars)",
            ))

            # olevba's built-in keyword scanner
            results = vp.analyze_macros(show_decoded_strings=False, deobfuscate=True)
            keyword_hits = []
            iocs = []
            for kw_type, keyword, description in results:
                if kw_type == "IOC":
                    iocs.append({"keyword": safe_string(keyword, 200), "description": safe_string(description, 200)})
                else:
                    keyword_hits.append({
                        "type": kw_type,
                        "keyword": safe_string(keyword, 100),
                        "description": safe_string(description, 200),
                    })

            if keyword_hits:
                # Severity heuristic: any Suspicious/AutoExec keyword is high
                high_types = {"AutoExec", "Suspicious"}
                sev = Severity.HIGH if any(h["type"] in high_types for h in keyword_hits) else Severity.MEDIUM
                ev.append(Evidence(
                    analyzer=self.name, field="macro_keywords", value=keyword_hits[:40],
                    severity=sev,
                    description=(
                        f"{len(keyword_hits)} olevba keyword hits in macros — "
                        "AutoExec triggers / Suspicious calls indicate weaponization"
                    ),
                ))

            if iocs:
                ev.append(Evidence(
                    analyzer=self.name, field="macro_iocs", value=iocs[:30],
                    severity=Severity.HIGH,
                    description=f"{len(iocs)} IOC(s) extracted from macros (URLs, IPs, file paths)",
                ))
        finally:
            try:
                vp.close()
            except Exception:
                pass

        return ev
