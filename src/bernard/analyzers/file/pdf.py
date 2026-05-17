"""PDF analyzer — looks for malicious indicators using PDFiD-style keyword counting."""
from __future__ import annotations
from pathlib import Path

from ...types import Evidence, Severity
from ..base import FileAnalyzer

# PDF keywords whose presence in elevated counts strongly suggests malicious intent
_DANGEROUS_KEYWORDS = [
    "/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm",
    "/Launch", "/EmbeddedFile", "/EmbeddedFiles", "/XFA",
    "/RichMedia", "/Encrypt", "/JBIG2Decode", "/ASCIIHexDecode",
]


class PDFAnalyzer(FileAnalyzer):
    name = "pdf"

    def supports(self, path: Path, magic_type: str) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read(5) == b"%PDF-"
        except OSError:
            return False

    def analyze(self, path: Path) -> list[Evidence]:
        data = path.read_bytes()
        counts: dict[str, int] = {}
        for kw in _DANGEROUS_KEYWORDS:
            counts[kw] = data.count(kw.encode())

        present = {k: v for k, v in counts.items() if v > 0}

        # /Pages count gives us total pages for sanity
        try:
            pages = data.count(b"/Page ") + data.count(b"/Page\n") + data.count(b"/Page<")
        except Exception:
            pages = 0

        ev: list[Evidence] = [
            Evidence(
                analyzer=self.name, field="header",
                value=(data[:8].decode("ascii", errors="replace")),
                severity=Severity.INFO, description="PDF header line",
            ),
            Evidence(
                analyzer=self.name, field="estimated_pages", value=pages,
                severity=Severity.INFO, description=f"Approximate page count: {pages}",
            ),
            Evidence(
                analyzer=self.name, field="dangerous_keywords", value=present,
                severity=Severity.HIGH if any(
                    k in present for k in ("/JS", "/JavaScript", "/Launch", "/EmbeddedFile", "/AA", "/OpenAction")
                ) else (Severity.MEDIUM if present else Severity.INFO),
                description=(
                    "Counts of PDF keywords associated with malicious behavior (JavaScript, "
                    "auto-actions, launchers, embedded files, forms). Any presence warrants scrutiny."
                ),
            ),
        ]

        # Heuristic: very short PDFs with many JS triggers are textbook exploit-droppers
        if pages <= 2 and any(present.get(k, 0) > 0 for k in ("/JS", "/JavaScript", "/OpenAction", "/AA")):
            ev.append(Evidence(
                analyzer=self.name, field="dropper_heuristic",
                value="short_pdf_with_active_content",
                severity=Severity.HIGH,
                description=(
                    "PDF has <=2 pages but contains JavaScript or auto-open actions — "
                    "classic shape of a malicious dropper rather than a real document"
                ),
            ))

        return ev
