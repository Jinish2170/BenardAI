"""PE (Windows executable) analyzer using LIEF."""
from __future__ import annotations
from pathlib import Path

from ...types import Evidence, Severity
from ..base import FileAnalyzer, safe_list, safe_string

# Imports commonly abused by malware (not exhaustive; for triage signal only)
_SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetWindowsHookEx", "LoadLibraryA", "GetProcAddress",
    "VirtualProtect", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
    "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "WinHttpOpen",
    "WSASocketA", "send", "recv", "connect",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "RegSetValueExA", "RegCreateKeyExA",   # persistence
    "ShellExecuteA", "WinExec", "CreateProcessA",
}


def _safe(getter, default=None):
    try:
        return getter()
    except Exception:
        return default


class PEAnalyzer(FileAnalyzer):
    name = "pe"

    def supports(self, path: Path, magic_type: str) -> bool:
        if "PE32" in magic_type or "MS-DOS executable" in magic_type or "MZ" in magic_type:
            return True
        # Fallback: sniff magic bytes
        try:
            with open(path, "rb") as fh:
                return fh.read(2) == b"MZ"
        except OSError:
            return False

    def analyze(self, path: Path) -> list[Evidence]:
        try:
            import lief
        except ImportError:
            return [Evidence(
                analyzer=self.name, field="error", value="lief not installed",
                severity=Severity.INFO, description="LIEF Python package missing; skipping PE analysis",
            )]

        # LIEF is noisy on stderr for malformed PEs; silence it
        try:
            lief.logging.disable()
        except Exception:
            pass

        try:
            binary = lief.parse(str(path))
        except Exception as exc:
            return [Evidence(
                analyzer=self.name, field="parse_error", value=str(exc)[:200],
                severity=Severity.LOW, description="LIEF could not parse this file as PE",
            )]

        if binary is None or not hasattr(binary, "imported_functions"):
            return []

        ev: list[Evidence] = []

        # Header info
        header = _safe(lambda: binary.header)
        opt = _safe(lambda: binary.optional_header)
        machine = safe_string(_safe(lambda: header.machine.name, "")) if header else ""
        timestamp = _safe(lambda: header.time_date_stamps, 0) if header else 0
        subsystem = safe_string(_safe(lambda: opt.subsystem.name, "")) if opt else ""
        entry_point = _safe(lambda: opt.addressof_entrypoint, 0) if opt else 0

        ev.append(Evidence(
            analyzer=self.name, field="machine", value=machine or "unknown",
            severity=Severity.INFO, description=f"PE machine type: {machine}",
        ))
        ev.append(Evidence(
            analyzer=self.name, field="subsystem", value=subsystem or "unknown",
            severity=Severity.INFO,
            description=f"PE subsystem: {subsystem} (GUI/console/native/etc.)",
        ))
        ev.append(Evidence(
            analyzer=self.name, field="compile_timestamp", value=timestamp,
            severity=Severity.INFO,
            description=f"Compile timestamp: {timestamp} (epoch seconds; 0 or future = suspicious)",
        ))
        ev.append(Evidence(
            analyzer=self.name, field="entry_point_rva", value=hex(entry_point),
            severity=Severity.INFO, description=f"Entry point RVA: {hex(entry_point)}",
        ))

        # Sections + entropy
        sections = list(_safe(lambda: list(binary.sections), []) or [])
        high_entropy_sections = []
        section_summary = []
        for s in sections:
            try:
                ent = round(s.entropy, 3)
                name = safe_string(s.name, 24)
                size = s.size
                section_summary.append({"name": name, "size": size, "entropy": ent})
                if ent > 7.2 and size > 1024:
                    high_entropy_sections.append({"name": name, "entropy": ent, "size": size})
            except Exception:
                continue

        if section_summary:
            ev.append(Evidence(
                analyzer=self.name, field="sections", value=section_summary[:20],
                severity=Severity.INFO,
                description=f"{len(section_summary)} sections; entropy >7.2 may indicate packing",
            ))
        if high_entropy_sections:
            ev.append(Evidence(
                analyzer=self.name, field="high_entropy_sections", value=high_entropy_sections,
                severity=Severity.HIGH,
                description=(
                    f"{len(high_entropy_sections)} section(s) have entropy > 7.2 — "
                    "strong indicator of packing or encryption (UPX, custom packers, embedded payloads)"
                ),
            ))

        # Imports — both raw list and suspicious-subset
        imports_by_lib: dict[str, list[str]] = {}
        all_imports: list[str] = []
        for lib in _safe(lambda: list(binary.imports), []) or []:
            try:
                lib_name = safe_string(lib.name, 80)
                funcs = []
                for entry in lib.entries:
                    fname = safe_string(getattr(entry, "name", ""), 80) or f"#{getattr(entry, 'ordinal', '?')}"
                    funcs.append(fname)
                imports_by_lib[lib_name] = funcs[:200]
                all_imports.extend(funcs)
            except Exception:
                continue

        if imports_by_lib:
            ev.append(Evidence(
                analyzer=self.name, field="imports_by_library",
                value={k: v[:30] for k, v in list(imports_by_lib.items())[:25]},
                severity=Severity.INFO,
                description=f"Imports {sum(len(v) for v in imports_by_lib.values())} functions from {len(imports_by_lib)} libraries",
            ))

        suspicious_found = sorted(set(all_imports) & _SUSPICIOUS_IMPORTS)
        if suspicious_found:
            ev.append(Evidence(
                analyzer=self.name, field="suspicious_imports", value=suspicious_found,
                severity=Severity.HIGH if len(suspicious_found) >= 4 else Severity.MEDIUM,
                description=(
                    f"Imports {len(suspicious_found)} APIs commonly abused by malware "
                    "(process injection, persistence, network, anti-debug, crypto-ransomware patterns)"
                ),
            ))

        # imphash and authentihash
        imphash = _safe(lambda: lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.DEFAULT))
        if imphash:
            ev.append(Evidence(
                analyzer=self.name, field="imphash", value=imphash,
                severity=Severity.INFO,
                description="PE imphash — identical imphash across samples often clusters into the same malware family",
            ))

        # Signed?
        is_signed = bool(_safe(lambda: list(binary.signatures), []))
        ev.append(Evidence(
            analyzer=self.name, field="is_signed", value=is_signed,
            severity=Severity.INFO if is_signed else Severity.LOW,
            description="Digitally signed" if is_signed else "Unsigned binary",
        ))

        # Overlay (data appended after the last section — common malware staging)
        try:
            overlay = bytes(binary.overlay)
            if overlay and len(overlay) > 256:
                ev.append(Evidence(
                    analyzer=self.name, field="overlay_size", value=len(overlay),
                    severity=Severity.MEDIUM,
                    description=(
                        f"PE has {len(overlay)} bytes of overlay (data after last section) — "
                        "often used to smuggle a second-stage payload or installer data"
                    ),
                ))
        except Exception:
            pass

        return ev
