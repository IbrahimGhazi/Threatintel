"""
Static file analyzer — inspects a file without executing it.

Produces:
  - File type, hashes, overall entropy
  - PE header: imports, exports, sections, compile timestamp
  - Per-section entropy (packer / encryption detection)
  - String extraction: printable ASCII + UTF-16LE
  - IOC extraction from strings: IPs, URLs, domains, registry keys, paths, mutexes
  - Packer / protector detection (signatures + section names)
  - Suspicious import scoring
  - Office macro presence detection
  - PDF embedded object detection
  - Overall suspicion score with reasons
"""
import hashlib
import math
import re
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Regex ─────────────────────────────────────────────────────────────────────

RE_URL      = re.compile(r'https?://[^\s\x00-\x1f"\'<>\\]{4,200}', re.IGNORECASE)
RE_IP       = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
RE_DOMAIN   = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}'
    r'(?:com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|club|site|online|'
    r'icu|tk|ml|ga|cf|gq|pw|cc|tv|co|us|ca|au|jp|br|in|fr|it|es|nl|se)\b',
    re.IGNORECASE,
)
RE_EMAIL    = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
RE_REGKEY   = re.compile(
    r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|HKU|HKCC)'
    r'(?:\\[^\x00-\x1f\\"]{1,128})+',
    re.IGNORECASE,
)
RE_PATH_WIN = re.compile(
    r'[C-Za-z]:\\(?:[^\x00-\x1f\\/:*?"<>|\r\n]+\\)*[^\x00-\x1f\\/:*?"<>|\r\n]+',
    re.IGNORECASE,
)
RE_MUTEX    = re.compile(r'Global\\[A-Za-z0-9_\-{}[\]{4,64}]')
RE_B64      = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# ── PE suspicious imports ─────────────────────────────────────────────────────

SUSPICIOUS_IMPORTS = {
    # Process injection
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    # Process hollowing
    "ZwUnmapViewOfSection", "NtUnmapViewOfSection", "NtWriteVirtualMemory",
    # Reflective DLL
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    # Crypto / ransomware
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
    "CryptHashData", "BCryptEncrypt", "BCryptGenRandom",
    # Anti-analysis / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "GetSystemTimeAsFileTime", "NtSetInformationThread",
    "CreateToolhelp32Snapshot", "NtQuerySystemInformation",
    # Keylogging / spying
    "GetAsyncKeyState", "GetKeyState", "RegisterHotKey",
    # Screenshot
    "BitBlt", "PrintWindow",
    # Network download
    "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
    "InternetOpenUrl", "InternetReadFile",
    # Registry persistence
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyEx", "RegCreateKeyExA",
    # Service persistence
    "CreateService", "CreateServiceA", "OpenSCManager",
    # Shellcode / in-memory exec
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "RtlDecompressBuffer", "RtlMoveMemory",
    # Token / privilege abuse
    "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
    # UAC bypass
    "ShellExecuteEx", "ShellExecuteExA",
}

# Severity weight per import category
IMPORT_SEVERITY: Dict[str, int] = {
    "VirtualAllocEx": 15, "WriteProcessMemory": 15, "CreateRemoteThread": 20,
    "NtCreateThreadEx": 20, "ZwUnmapViewOfSection": 20,
    "SetWindowsHookEx": 10, "SetWindowsHookExA": 10,
    "IsDebuggerPresent": 5, "CheckRemoteDebuggerPresent": 5,
    "CryptEncrypt": 10, "BCryptEncrypt": 10,
    "GetAsyncKeyState": 15,
    "URLDownloadToFile": 10,
    "AdjustTokenPrivileges": 10,
}

# Known malware signatures — checked against every file and every ZIP member
# Key: byte pattern, Value: (display_name, base_score)
KNOWN_SIGNATURES: List[tuple] = [
    (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
     "EICAR-Test-File", 100),
    (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
     "EICAR-Test-File (partial)", 80),
    # Metasploit shellcode prologue patterns
    (b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30",
     "Metasploit/shellcode-prologue", 85),
    # Common Mimikatz string
    (b"sekurlsa::logonpasswords",
     "Mimikatz-credential-dumper", 95),
    (b"sekurlsa::wdigest",
     "Mimikatz-credential-dumper", 95),
    # WannaCry killswitch domain
    (b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
     "WannaCry-killswitch-domain", 95),
    # Cobalt Strike default watermarks in stagers
    (b"\x2e\x2f\x2f\x36\x6f\x35\x64\x2f\x36\x6e\x35\x64\x2f",
     "CobaltStrike-stager-pattern", 80),
]

# Known packer byte signatures
PACKER_SIGS = [
    (b"UPX!",           "UPX"),
    (b"MPRESS1",        "MPRESS"),
    (b"PECompact",      "PECompact"),
    (b".aspack",        "ASPack"),
    (b"Themida",        "Themida"),
    (b"Obsidium",       "Obsidium"),
    (b"nSPack",         "nSPack"),
    (b".petite",        "Petite"),
    (b"ENIGMA",         "Enigma Protector"),
    (b"VMProtect",      "VMProtect"),
    (b"ConfuserEx",     "ConfuserEx (.NET)"),
    (b"SmartAssembly",  "SmartAssembly (.NET)"),
]

# PE section names associated with packers
PACKER_SECTIONS = frozenset({
    "UPX0", "UPX1", "UPX2",
    ".aspack", ".adata", "ASPack",
    ".MPRESS1", ".MPRESS2",
    "Themida", ".themida",
    ".petite", ".nsp0", ".nsp1", ".nsp2",
})


class StaticAnalyzer:

    def analyze(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            data = f.read()

        result: Dict[str, Any] = {
            "file_size":          len(data),
            "file_type":          _detect_type(data),
            "hashes":             _compute_hashes(data),
            "entropy":            _entropy(data),
            "strings":            [],
            "iocs":               {
                "ips": [], "domains": [], "urls": [], "emails": [],
                "registry_keys": [], "file_paths": [], "mutexes": [],
                "base64_blobs": [],
            },
            "pe":                 None,
            "packers":            [],
            "suspicious_score":   0,
            "suspicious_reasons": [],
        }

        # ── Known malware signatures ──────────────────────────────────────────
        _scan_known_signatures(data, result)

        # ── Packer signatures (raw file scan) ─────────────────────────────────
        for sig, name in PACKER_SIGS:
            if sig in data:
                result["packers"].append(name)

        # ── String extraction ─────────────────────────────────────────────────
        strings = _extract_strings(data)
        result["strings"] = strings[:500]
        all_text = "\n".join(strings)

        result["iocs"]["urls"]          = list(dict.fromkeys(RE_URL.findall(all_text)))[:50]
        result["iocs"]["ips"]           = list(dict.fromkeys(RE_IP.findall(all_text)))[:50]
        result["iocs"]["domains"]       = list(dict.fromkeys(RE_DOMAIN.findall(all_text)))[:50]
        result["iocs"]["emails"]        = list(dict.fromkeys(RE_EMAIL.findall(all_text)))[:20]
        result["iocs"]["registry_keys"] = list(dict.fromkeys(RE_REGKEY.findall(all_text)))[:30]
        result["iocs"]["file_paths"]    = list(dict.fromkeys(RE_PATH_WIN.findall(all_text)))[:30]
        result["iocs"]["mutexes"]       = list(dict.fromkeys(RE_MUTEX.findall(all_text)))[:20]

        # Long base64 blobs suggest encoded payload
        b64_hits = [m for m in RE_B64.findall(all_text) if len(m) > 60]
        result["iocs"]["base64_blobs"] = b64_hits[:5]

        # ── Format-specific analysis ──────────────────────────────────────────
        if data[:2] == b"MZ":
            result["pe"] = self._analyze_pe(data, result)
        elif data[:4] == b"\xd0\xcf\x11\xe0":
            result["office"] = self._analyze_ole(data, result)
        elif data[:4] == b"%PDF":
            result["pdf"] = self._analyze_pdf(data, result)
        elif data[:4] == b"PK\x03\x04":
            result["zip"] = self._analyze_zip(data, result)

        # ── Scoring ───────────────────────────────────────────────────────────
        self._score(result)
        return result

    # ── PE ────────────────────────────────────────────────────────────────────

    def _analyze_pe(self, data: bytes, result: dict) -> Optional[Dict[str, Any]]:
        try:
            import pefile  # type: ignore
        except ImportError:
            result["suspicious_reasons"].append("pefile not available — PE analysis skipped")
            return None

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except Exception as exc:
            result["suspicious_reasons"].append(f"Malformed PE header: {exc}")
            return {"error": str(exc)}

        pe_info: Dict[str, Any] = {
            "machine":            hex(pe.FILE_HEADER.Machine),
            "characteristics":    hex(pe.FILE_HEADER.Characteristics),
            "is_dll":             bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "is_driver":          pe.OPTIONAL_HEADER.Subsystem == 1,
            "subsystem":          pe.OPTIONAL_HEADER.Subsystem,
            "compile_timestamp":  "",
            "sections":           [],
            "imports":            {},
            "exports":            [],
            "tls_callbacks":      False,
            "has_overlay":        False,
            "suspicious_imports": [],
            "import_score":       0,
        }

        # Compile timestamp
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            pe_info["compile_timestamp"] = (
                datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            )
            # Timestamp in the future or before 1995 → likely forged
            now = datetime.now(tz=timezone.utc).timestamp()
            if ts > now or ts < 788918400:   # < 1995-01-01
                result["suspicious_reasons"].append(
                    f"PE compile timestamp suspicious: {pe_info['compile_timestamp']}"
                )
        except Exception:
            pass

        # Sections
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            raw  = section.get_data()
            ent  = _entropy(raw)
            info = {
                "name":             name,
                "virtual_size":     section.Misc_VirtualSize,
                "raw_size":         section.SizeOfRawData,
                "entropy":          ent,
                "characteristics":  hex(section.Characteristics),
                "is_executable":    bool(section.Characteristics & 0x20000000),
                "is_writable":      bool(section.Characteristics & 0x80000000),
            }
            pe_info["sections"].append(info)

            # Packer section name
            stripped = name.strip()
            if stripped in PACKER_SECTIONS:
                result["packers"].append(f"packer-section:{stripped}")

            # High entropy in executable section → packed/encrypted
            if ent > 7.0 and section.SizeOfRawData > 4096:
                result["suspicious_reasons"].append(
                    f"High-entropy section '{name}' ({ent:.2f}/8.0) — packed or encrypted payload"
                )

            # Writable+Executable section → shellcode
            if info["is_executable"] and info["is_writable"]:
                result["suspicious_reasons"].append(
                    f"Section '{name}' is both writable and executable — shellcode indicator"
                )

        # Imports
        imp_score = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace").lower()
                funcs: List[str] = []
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode("utf-8", errors="replace")
                        funcs.append(fname)
                        if fname in SUSPICIOUS_IMPORTS:
                            pe_info["suspicious_imports"].append(f"{dll}!{fname}")
                            imp_score += IMPORT_SEVERITY.get(fname, 5)
                pe_info["imports"][dll] = funcs[:100]
        pe_info["import_score"] = min(imp_score, 100)

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    pe_info["exports"].append(
                        exp.name.decode("utf-8", errors="replace")
                    )

        # TLS callbacks (anti-analysis, often used to run code before entry point)
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            pe_info["tls_callbacks"] = True
            result["suspicious_reasons"].append(
                "PE has TLS callbacks — code runs before entry point (anti-analysis)"
            )

        # Overlay (data after the last section — common in droppers/stubs)
        last_section_end = max(
            (s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0
        )
        overlay_size = len(data) - last_section_end
        if overlay_size > 4096:
            pe_info["has_overlay"] = True
            pe_info["overlay_size"] = overlay_size
            result["suspicious_reasons"].append(
                f"PE overlay: {overlay_size:,} bytes of data after last section (dropper indicator)"
            )

        pe.close()
        return pe_info

    # ── Office (OLE) ──────────────────────────────────────────────────────────

    def _analyze_ole(self, data: bytes, result: dict) -> Dict[str, Any]:
        info: Dict[str, Any] = {"has_macros": False, "vba_code": [], "auto_exec": []}
        try:
            import olefile  # type: ignore
            import io
            ole = olefile.OleFileIO(io.BytesIO(data))

            # Check for VBA storage (indicator of macros)
            if ole.exists("Macros/VBA") or ole.exists("_VBA_PROJECT_CUR") \
                    or ole.exists("VBA"):
                info["has_macros"] = True
                result["suspicious_reasons"].append(
                    "Office document contains VBA macros"
                )

            ole.close()

            # Try oletools for deeper analysis
            try:
                from oletools.olevba import VBA_Parser  # type: ignore
                vba = VBA_Parser("sample.doc", data=data)
                if vba.detect_vba_macros():
                    info["has_macros"] = True
                    for (_filename, _stream, vba_filename, vba_code) in vba.extract_macros():
                        info["vba_code"].append(vba_code[:500])
                        # Check for auto-exec keywords
                        for kw in ("AutoOpen", "AutoExec", "Auto_Open",
                                   "Workbook_Open", "Document_Open",
                                   "Shell", "WScript", "PowerShell", "cmd.exe"):
                            if kw.lower() in vba_code.lower():
                                info["auto_exec"].append(kw)
                    if info["auto_exec"]:
                        result["suspicious_reasons"].append(
                            f"Macro auto-exec keywords: {', '.join(set(info['auto_exec']))}"
                        )
            except ImportError:
                pass

        except Exception as exc:
            info["error"] = str(exc)

        return info

    # ── PDF ───────────────────────────────────────────────────────────────────

    def _analyze_pdf(self, data: bytes, result: dict) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "javascript": False, "embedded_files": 0,
            "launch_actions": False, "obfuscated": False,
        }
        text = data.decode("latin-1", errors="replace")

        if re.search(r"/JavaScript\b", text, re.IGNORECASE):
            info["javascript"] = True
            result["suspicious_reasons"].append("PDF contains JavaScript")

        if re.search(r"/EmbeddedFile\b", text, re.IGNORECASE):
            info["embedded_files"] = len(re.findall(r"/EmbeddedFile", text, re.IGNORECASE))
            result["suspicious_reasons"].append(
                f"PDF has {info['embedded_files']} embedded file(s)"
            )

        if re.search(r"/Launch\b", text, re.IGNORECASE):
            info["launch_actions"] = True
            result["suspicious_reasons"].append("PDF has /Launch action — can execute external programs")

        if re.search(r"/AA\b", text, re.IGNORECASE):
            result["suspicious_reasons"].append("PDF has /AA (additional actions) — auto-execute trigger")

        # High count of hex-encoded or name-obfuscated objects
        hex_names = len(re.findall(r"#[0-9a-fA-F]{2}", text))
        if hex_names > 10:
            info["obfuscated"] = True
            result["suspicious_reasons"].append("PDF name obfuscation detected (hex-encoded names)")

        return info

    # ── ZIP ───────────────────────────────────────────────────────────────────

    def _analyze_zip(self, data: bytes, result: dict) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "files": [], "suspicious_files": [],
            "known_signatures": [], "member_scores": [],
        }
        try:
            import zipfile
            import io

            EXEC_EXTS = (
                ".exe", ".dll", ".vbs", ".js", ".ps1", ".bat", ".cmd",
                ".hta", ".scr", ".pif", ".com", ".elf", ".sh", ".py",
            )

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for zinfo in zf.infolist()[:200]:
                    name = zinfo.filename
                    info["files"].append(name)
                    lower = name.lower()

                    if any(lower.endswith(ext) for ext in EXEC_EXTS):
                        info["suspicious_files"].append(name)

                    # Read and inspect member content (skip very large members)
                    if zinfo.file_size > 20 * 1024 * 1024:
                        continue
                    try:
                        member_data = zf.read(zinfo)
                    except Exception:
                        continue

                    # Known malware signature scan on member content
                    for sig, sig_name, _ in KNOWN_SIGNATURES:
                        if sig in member_data:
                            hit = f"{sig_name} in {name}"
                            info["known_signatures"].append(hit)
                            result["suspicious_reasons"].append(
                                f"Known malware signature [{sig_name}] found in ZIP member: {name}"
                            )

                    # String extraction + IOC scan on member content
                    member_strings = _extract_strings(member_data)
                    member_text = "\n".join(member_strings)
                    for ip in RE_IP.findall(member_text):
                        if ip not in result["iocs"]["ips"]:
                            result["iocs"]["ips"].append(ip)
                    for url in RE_URL.findall(member_text):
                        if url not in result["iocs"]["urls"]:
                            result["iocs"]["urls"].append(url)
                    for domain in RE_DOMAIN.findall(member_text):
                        if domain not in result["iocs"]["domains"]:
                            result["iocs"]["domains"].append(domain)

                    # Format-specific analysis on PE members inside the ZIP
                    if member_data[:2] == b"MZ":
                        sub = {
                            "file_type": "PE/Windows Executable",
                            "entropy": _entropy(member_data),
                            "strings": member_strings[:100],
                            "iocs": {"ips": [], "domains": [], "urls": [],
                                     "emails": [], "registry_keys": [],
                                     "file_paths": [], "mutexes": [], "base64_blobs": []},
                            "packers": [],
                            "suspicious_score": 0,
                            "suspicious_reasons": [],
                        }
                        for psig, pname in PACKER_SIGS:
                            if psig in member_data:
                                sub["packers"].append(pname)
                        pe_info = self._analyze_pe(member_data, sub)
                        if pe_info:
                            member_score = min(pe_info.get("import_score", 0), 50)
                            if sub["packers"]:
                                member_score += 25
                            if pe_info.get("tls_callbacks"):
                                member_score += 10
                            if member_score > 0:
                                info["member_scores"].append((name, member_score))
                                result["suspicious_reasons"].append(
                                    f"Suspicious PE inside ZIP ({name}): score {member_score}"
                                )

                if info["suspicious_files"]:
                    result["suspicious_reasons"].append(
                        f"ZIP contains executable file(s): {info['suspicious_files'][:3]}"
                    )

        except Exception:
            pass
        return info

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, result: dict):
        score   = 0
        reasons = result["suspicious_reasons"]

        if result["packers"]:
            score += 25
            reasons.append(f"Packer/protector: {', '.join(set(result['packers']))}")

        if result["entropy"] > 7.2:
            score += 15
            reasons.append(f"High overall entropy ({result['entropy']:.2f}/8.0)")
        elif result["entropy"] > 6.8:
            score += 5

        pe = result.get("pe")
        if pe and isinstance(pe, dict):
            score += min(pe.get("import_score", 0), 30)
            if pe.get("suspicious_imports"):
                top = pe["suspicious_imports"][:3]
                reasons.append(f"Suspicious imports: {', '.join(top)}")
            if pe.get("is_driver"):
                score += 25
                reasons.append("PE is a kernel driver (SYSTEM-level access)")
            if pe.get("tls_callbacks"):
                score += 10
            if pe.get("has_overlay"):
                score += 10

        if result["iocs"]["ips"]:
            score += 5
        if result["iocs"]["urls"]:
            score += 5
        if result["iocs"]["registry_keys"]:
            score += 10
        if result["iocs"].get("base64_blobs"):
            score += 10
            reasons.append("Large base64 blobs detected (encoded payload likely)")

        # ── Known malware signatures hit (applies to raw file and ZIP members) ──
        for sig, sig_name, sig_score in KNOWN_SIGNATURES:
            if any(sig_name in r for r in reasons):
                score = max(score, sig_score)   # take the highest matching score
                reasons.append(f"Known malware signature matched: {sig_name}")
                break

        # ── ZIP-specific scoring ───────────────────────────────────────────────
        zip_info = result.get("zip")
        if zip_info and isinstance(zip_info, dict):
            if zip_info.get("known_signatures"):
                # Already handled above via suspicious_reasons propagation;
                # ensure score floors at 80 for any signature hit
                score = max(score, 80)
            if zip_info.get("suspicious_files"):
                score += 20
            for _name, ms in zip_info.get("member_scores", []):
                score += ms  # propagate PE-inside-ZIP scores

        office = result.get("office")
        if office and isinstance(office, dict):
            if office.get("has_macros"):
                score += 20
            if office.get("auto_exec"):
                score += 20

        pdf = result.get("pdf")
        if pdf and isinstance(pdf, dict):
            if pdf.get("javascript"):
                score += 15
            if pdf.get("launch_actions"):
                score += 20

        result["suspicious_score"] = min(score, 100)


# ── Utilities ──────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n   = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p   = f / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def _extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    strings: List[str] = []
    # ASCII
    for m in re.finditer(rb'[ -~]{%d,512}' % min_len, data):
        strings.append(m.group().decode("ascii", errors="ignore"))
    # UTF-16LE
    for m in re.finditer(rb'(?:[ -~]\x00){%d,512}' % min_len, data):
        try:
            s = m.group().decode("utf-16-le", errors="ignore").strip()
            if s:
                strings.append(s)
        except Exception:
            pass
    return list(dict.fromkeys(strings))  # deduplicate, preserve order


def _compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _scan_known_signatures(data: bytes, result: dict) -> None:
    """Check raw file bytes against KNOWN_SIGNATURES and populate suspicious_reasons."""
    for sig, sig_name, _ in KNOWN_SIGNATURES:
        if sig in data:
            result["suspicious_reasons"].append(
                f"Known malware signature matched: {sig_name}"
            )


def _detect_type(data: bytes) -> str:
    MAGIC: List[tuple] = [
        (b"MZ",             "PE/Windows Executable"),
        (b"\x7fELF",        "ELF/Linux Executable"),
        (b"PK\x03\x04",     "ZIP Archive"),
        (b"%PDF",           "PDF Document"),
        (b"\xd0\xcf\x11\xe0","Microsoft Office (OLE)"),
        (b"\xff\xd8\xff",   "JPEG Image"),
        (b"\x89PNG",        "PNG Image"),
        (b"GIF8",           "GIF Image"),
        (b"Rar!\x1a\x07",   "RAR Archive"),
        (b"\x1f\x8b",       "GZIP Archive"),
        (b"7z\xbc\xaf\x27\x1c","7-Zip Archive"),
        (b"CAFEBABE",       "Java Class"),
        (b"dex\n",          "Android DEX"),
        (b"\xca\xfe\xba\xbe","Java Class / Mach-O FAT"),
        (b"\xfe\xed\xfa\xce","Mach-O 32-bit"),
        (b"\xfe\xed\xfa\xcf","Mach-O 64-bit"),
    ]
    for magic, label in MAGIC:
        if data[:len(magic)] == magic:
            return label
    # Script detection
    try:
        head = data[:512].decode("utf-8")
        if head.startswith("#!"):
            if any(x in head.split("\n")[0] for x in ("python", "python3")):
                return "Python Script"
            return "Shell/Script"
        if "<?php" in head[:64].lower():
            return "PHP Script"
        if head.strip().startswith("<html") or head.strip().startswith("<!DOCTYPE"):
            return "HTML"
        if head.strip().startswith("{") or head.strip().startswith("["):
            return "JSON"
        if head.strip().startswith("<?xml") or head.strip().startswith("<"):
            return "XML"
        # Python: detect common top-level patterns without requiring a shebang
        import re as _re
        _py_pat = _re.compile(
            r'^(?:import \w|from \w[\w.]* import |def \w|class \w|if __name__|async def \w)',
            _re.MULTILINE,
        )
        if _py_pat.search(head):
            return "Python Script"
        # PowerShell
        if any(x in head for x in ("param(", "Param(", "Write-Host", "Get-", "Set-", "New-")):
            return "PowerShell Script"
        # Windows batch
        if any(x in head.lower() for x in ("@echo off", "@echo on", "set /p ", "goto ", "endlocal")):
            return "Batch Script"
    except (UnicodeDecodeError, ValueError):
        pass
    return "Unknown Binary"
