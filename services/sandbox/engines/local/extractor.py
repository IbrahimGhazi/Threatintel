"""
IOC extractor — parses raw analysis artifacts into structured indicators.

Handles:
  - strace syscall logs  → network connections, executed commands, file ops
  - PCAP bytes           → DNS queries, HTTP requests, IP addresses
  - inotifywait logs     → filesystem events, persistence, ransomware patterns
  - Behavioral scoring   → injection, evasion, C2, exfiltration
"""
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

# ── Regex patterns ─────────────────────────────────────────────────────────────

RE_IP       = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
RE_DOMAIN   = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}'
    r'(?:com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|club|site|online|'
    r'icu|tk|ml|ga|cf|gq|pw|cc|tv|co|us|ca|au|jp|br|in|fr|it|es|nl|'
    r'se|no|dk|fi|pl|cz|sk|hu|ro|bg|gr|tr|il|sa|ae|za|ng|ke|eg)\b',
    re.IGNORECASE,
)
RE_URL      = re.compile(r'https?://[^\s\x00-\x1f"\'<>\\]{4,200}', re.IGNORECASE)
RE_CONNECT  = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\),\s*'
    r'sin6?_addr(?:6)?=inet(?:6)?_addr\("([^"]+)"\)'
)
RE_EXECVE   = re.compile(r'execve\("([^"]+)"')
RE_OPENAT   = re.compile(r'open(?:at)?\([^,]*"([^"]+)",\s*([^)]+)\)')
RE_GETADDR  = re.compile(r'getaddrinfo\("([^"]+)"')
RE_MMAP     = re.compile(r'mmap\([^)]+PROT_WRITE[^)]*PROT_EXEC|PROT_EXEC[^)]*PROT_WRITE')
RE_PTRACE   = re.compile(r'ptrace\(PTRACE_TRACEME')
RE_SETUID   = re.compile(r'(?:setuid|setgid|setreuid|setresuid|capset)\(')
RE_UNLINK   = re.compile(r'unlinkat?\([^,]*"([^"]+)"')
RE_SCHED    = re.compile(r'(crontab|cron\.d|at\s+\d|systemctl\s+enable)', re.IGNORECASE)
RE_CHMOD_X  = re.compile(r'chmod\("([^"]+)",\s*0o?([0-7]+)\)')
RE_MEMFD    = re.compile(r'memfd_create\(')
RE_CLONE    = re.compile(r'(?:clone|fork|vfork)\(')

# Paths indicating persistence mechanisms
PERSISTENCE_PATHS = (
    "/etc/cron", "/var/spool/cron", "/etc/init.d", "/etc/rc",
    "/etc/systemd/system", "/usr/lib/systemd/system",
    "/etc/profile", "/etc/bashrc", "/.bashrc", "/.profile",
    "/etc/sudoers", "/etc/ld.so.preload",
    "\\CurrentVersion\\Run", "\\Startup\\",
    "/usr/local/bin/", "/usr/bin/",
)

# Sensitive paths that should not be accessed by normal programs
SENSITIVE_PATHS = (
    "/etc/shadow", "id_rsa", "authorized_keys", ".ssh/",
    "wallet.dat", ".gnupg/", "secring.gpg", "/etc/ssl/private",
    "/.aws/credentials", "/.kube/config",
)

# VM/Sandbox detection artifacts the sample might check
ANTI_VM_ARTIFACTS = (
    "vmci", "vmhgfs", "vmsys", "vmx86",            # VMware
    "vboxguest", "vboxsf", "vboxvideo",             # VirtualBox
    "qemu-ga", "virtio", "qxl",                     # QEMU/KVM
    "sbiedll", "sbiehook",                          # Sandboxie
    "api_log.dll", "dir_watch.dll",                 # Anubis
    "prl_", "parallels",                            # Parallels
    "cuckoomon", "cuckoo",                          # Cuckoo
    "wireshark", "procmon", "ollydbg", "x64dbg",   # Analysis tools
)

RANSOMWARE_EXTENSIONS = frozenset({
    ".locked", ".encrypted", ".enc", ".crypted", ".crypto",
    ".ransom", ".pay", ".wallet", ".wcry", ".wncry", ".wnry",
    ".ryuk", ".conti", ".revil", ".lockbit",
})


class IOCExtractor:

    # ── strace ─────────────────────────────────────────────────────────────────

    def extract_from_strace(self, strace_text: str) -> Dict[str, Any]:
        ips:          set  = set()
        domains:      set  = set()
        commands:     list = []
        files_read:   set  = set()
        files_written:set  = set()
        files_deleted:set  = set()
        connections:  list = []
        child_procs:  int  = 0
        memfd_used:   bool = False
        behavioral:   list = []

        for line in strace_text.splitlines():
            # Network: connect()
            m = RE_CONNECT.search(line)
            if m:
                port_s, ip = m.group(1), m.group(2)
                if not _is_local(ip):
                    ips.add(ip)
                    connections.append({"ip": ip, "port": int(port_s)})

            # DNS: getaddrinfo()
            m = RE_GETADDR.search(line)
            if m:
                name = m.group(1)
                if "." in name and not RE_IP.match(name):
                    domains.add(name)

            # Process creation: execve()
            m = RE_EXECVE.search(line)
            if m:
                commands.append(m.group(1))

            # Process creation: fork/clone
            if RE_CLONE.search(line):
                child_procs += 1

            # File ops: open/openat()
            m = RE_OPENAT.search(line)
            if m:
                path, flags = m.group(1), m.group(2)
                if path.startswith(("/proc", "/sys", "/dev", "/run")):
                    pass
                elif any(x in flags for x in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")):
                    files_written.add(path)
                else:
                    files_read.add(path)

            # File deletion
            m = RE_UNLINK.search(line)
            if m:
                files_deleted.add(m.group(1))

            # Code injection: WRITE+EXEC mmap
            if RE_MMAP.search(line):
                _append_once(behavioral, "memory_exec",
                    "mmap with WRITE+EXEC permissions — possible code injection / shellcode unpacking",
                    "high")

            # Anonymous executable memory (fileless execution)
            if RE_MEMFD.search(line):
                memfd_used = True
                _append_once(behavioral, "fileless_exec",
                    "memfd_create() used — fileless/in-memory execution technique",
                    "critical")

            # Anti-debugging
            if RE_PTRACE.search(line):
                _append_once(behavioral, "anti_debug",
                    "PTRACE_TRACEME — sample checked for attached debugger",
                    "medium")

            # Privilege escalation
            if RE_SETUID.search(line):
                _append_once(behavioral, "privesc",
                    f"Privilege change syscall: {line.strip()[:80]}",
                    "high")

        # Persistence indicators
        for path in files_written:
            for ppath in PERSISTENCE_PATHS:
                if ppath in path:
                    _add_behavioral(behavioral, "persistence",
                        f"Wrote to persistence location: {path}", "high")
                    break

        # Sensitive file access
        for path in files_read:
            for spath in SENSITIVE_PATHS:
                if spath in path:
                    _add_behavioral(behavioral, "sensitive_access",
                        f"Read sensitive file: {path}", "high")
                    break

        # Anti-VM checks
        for path in files_read | files_written:
            for artifact in ANTI_VM_ARTIFACTS:
                if artifact in path.lower():
                    _add_behavioral(behavioral, "anti_vm",
                        f"Checked for analysis/VM artifact: {path}", "medium")
                    break

        # Beaconing detection
        beaconing = _detect_beaconing(connections)
        if beaconing:
            _add_behavioral(behavioral, "c2_beacon",
                f"C2 beaconing to {beaconing['ip']}:{beaconing['port']} "
                f"({beaconing['count']} repeated connections)", "critical")
            ips.add(beaconing["ip"])

        # Many child processes (worm/dropper behaviour)
        if child_procs > 10:
            _add_behavioral(behavioral, "process_bomb",
                f"Created {child_procs} child processes — worm/fork-bomb behaviour",
                "high")

        return {
            "ips":            list(ips),
            "domains":        list(domains),
            "executed_commands": commands[:50],
            "files_read":     list(files_read)[:50],
            "files_written":  list(files_written)[:50],
            "files_deleted":  list(files_deleted)[:50],
            "connections":    connections[:100],
            "behavioral":     behavioral,
        }

    # ── PCAP ───────────────────────────────────────────────────────────────────

    def extract_from_pcap(self, pcap_data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ips": [], "domains": [], "urls": [],
            "dns_queries": [], "http_requests": [],
            "bytes_sent": 0, "exfiltration_suspected": False,
        }
        if not pcap_data:
            return result

        try:
            import dpkt
            import io

            pcap      = dpkt.pcap.Reader(io.BytesIO(pcap_data))
            ips_seen  = set()
            dns_seen  = set()
            http_reqs = []
            total_out = 0

            for _ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip  = eth.data
                    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue

                    if isinstance(ip, dpkt.ip.IP):
                        dst = ".".join(str(b) for b in ip.dst)
                        if not _is_local(dst):
                            ips_seen.add(dst)
                    else:
                        dst = str(ip.dst)

                    transport = ip.data

                    # DNS (UDP port 53)
                    if isinstance(transport, dpkt.udp.UDP) and transport.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(transport.data)
                            for q in dns.qd:
                                if q.name and "." in q.name:
                                    dns_seen.add(q.name)
                        except Exception:
                            pass

                    # HTTP (TCP)
                    elif isinstance(transport, dpkt.tcp.TCP) and transport.data:
                        total_out += len(transport.data)
                        try:
                            req  = dpkt.http.Request(transport.data)
                            host = req.headers.get("host", dst)
                            http_reqs.append({
                                "method": req.method.decode() if isinstance(req.method, bytes) else req.method,
                                "url": f"http://{host}{req.uri}",
                                "host": host,
                                "user_agent": req.headers.get("user-agent", ""),
                            })
                        except Exception:
                            pass

                except Exception:
                    continue

            result["ips"]           = list(ips_seen)[:50]
            result["domains"]       = list(dns_seen)[:50]
            result["dns_queries"]   = list(dns_seen)[:50]
            result["http_requests"] = http_reqs[:50]
            result["urls"]          = [r["url"] for r in http_reqs][:50]
            result["bytes_sent"]    = total_out
            if total_out > 1_000_000:   # >1 MB outbound
                result["exfiltration_suspected"] = True

        except ImportError:
            pass  # dpkt optional
        except Exception:
            pass

        return result

    # ── Filesystem events (inotifywait) ────────────────────────────────────────

    def extract_from_fs_events(self, events_text: str) -> Dict[str, Any]:
        created:  list = []
        modified: list = []
        deleted:  list = []
        persist:  list = []
        ransom:   list = []

        for line in events_text.splitlines():
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            _ts, event, path = parts[0], parts[1].upper(), parts[2]

            if "CREATE" in event:
                created.append(path)
            if "MODIFY" in event or "CLOSE_WRITE" in event:
                modified.append(path)
            if "DELETE" in event or "MOVED_FROM" in event:
                deleted.append(path)

        # Persistence
        for path in created + modified:
            for pp in PERSISTENCE_PATHS:
                if pp in path:
                    persist.append({"path": path,
                                    "description": "Written to persistence location"})
                    break

        # Ransomware: suspicious extensions or mass modification
        sus_ext = sum(1 for p in created + modified
                      if any(p.endswith(e) for e in RANSOMWARE_EXTENSIONS))
        if sus_ext >= 3:
            ransom.append({"description": f"Files with ransomware extensions created: {sus_ext}"})
        if len(modified) > 80:
            ransom.append({"description":
                f"Mass filesystem modification: {len(modified)} files altered"})

        return {
            "files_created":          created[:50],
            "files_modified":         modified[:50],
            "files_deleted":          deleted[:50],
            "persistence_indicators": persist,
            "ransomware_indicators":  ransom,
        }

    # ── Dropped file hashes ────────────────────────────────────────────────────

    def extract_dropped_hashes(self, hash_log: str) -> List[str]:
        hashes = []
        for line in hash_log.splitlines():
            parts = line.split()
            if parts:
                h = parts[0].strip()
                if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                    hashes.append(h)
        return hashes


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_local(ip: str) -> bool:
    return (ip.startswith(("127.", "10.", "172.16.", "172.17.", "192.168.", "::1", "fe80"))
            or ip in ("0.0.0.0", "255.255.255.255"))


def _detect_beaconing(connections: List[Dict]) -> Optional[Dict]:
    if len(connections) < 3:
        return None
    ctr = Counter((c["ip"], c["port"]) for c in connections)
    (ip, port), count = ctr.most_common(1)[0]
    if count >= 3:
        return {"ip": ip, "port": port, "count": count}
    return None


_seen: Dict[str, set] = defaultdict(set)


def _append_once(lst: list, kind: str, desc: str, sev: str):
    """Add behavioral indicator, deduplicated by kind."""
    for item in lst:
        if item["type"] == kind:
            return
    lst.append({"type": kind, "description": desc, "severity": sev})


def _add_behavioral(lst: list, kind: str, desc: str, sev: str):
    """Add behavioral indicator (allows multiple of same kind)."""
    lst.append({"type": kind, "description": desc, "severity": sev})
