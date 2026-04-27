"""
Dynamic analyzer — executes the sample inside an isolated Docker container
and collects behavioral telemetry:

  strace     → syscalls (process creation, file ops, network, memory)
  tcpdump    → raw network traffic (PCAP)
  inotifywait→ filesystem events
  libfaketime→ clock fast-forward to trigger delayed payloads
  xdotool    → simulated user activity (mouse, keyboard)
  /proc scan → memory maps, loaded modules after execution

The analysis container is ephemeral, network-isolated, and resource-capped.
After the timeout the container is killed and all artifacts are collected.
"""
import asyncio
import logging
import os
import tarfile
import io
import tempfile
from typing import Any, Dict, Optional

from .extractor import IOCExtractor

log = logging.getLogger(__name__)

ANALYSIS_IMAGE   = os.getenv("SANDBOX_ANALYSIS_IMAGE", "ti-sandbox-analysis:latest")
ANALYSIS_TIMEOUT = int(os.getenv("SANDBOX_ANALYSIS_TIMEOUT", "120"))  # seconds

# ── Analysis script embedded as a string (injected into the container) ─────────
_ANALYSIS_SH = r"""#!/bin/bash
set -euo pipefail

SAMPLE="$1"
OUTPUT="$2"
TIMEOUT="${3:-120}"
FILE_NAME="$(basename "$SAMPLE")"

mkdir -p "$OUTPUT"

# ── Fake environment (defeat anti-VM / anti-sandbox checks) ──────────────────
export HOME=/home/analyst
export USER=analyst
export USERNAME=analyst
export COMPUTERNAME=DESKTOP-$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 8 | tr a-z A-Z)
export PROCESSOR_IDENTIFIER="Intel64 Family 6 Model 165 Stepping 2, GenuineIntel"
export DISPLAY=:0
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /home/analyst/Desktop /home/analyst/Documents /home/analyst/Downloads

# ── Fake recently-opened documents (user simulation) ─────────────────────────
for f in report_Q4.docx invoice_2024.xlsx presentation.pptx; do
    touch "/home/analyst/Documents/$f"
done

# ── Time: advance clock 2 weeks to trigger delayed payloads ──────────────────
FAKE_TIME="+14d"

# ── Start filesystem monitor ──────────────────────────────────────────────────
if command -v inotifywait &>/dev/null; then
    inotifywait -r -m -e create,modify,delete,move,close_write \
        --format '%T|%e|%w%f' --timefmt '%s' \
        /tmp /home /root /etc /var/spool /usr/local/bin /usr/bin 2>/dev/null \
        >> "$OUTPUT/fs_events.log" &
    INOTIFY_PID=$!
fi

# ── Start network capture ─────────────────────────────────────────────────────
if command -v tcpdump &>/dev/null; then
    tcpdump -i any -w "$OUTPUT/capture.pcap" -G "$TIMEOUT" -W 1 -q 2>/dev/null &
    TCPDUMP_PID=$!
fi

# ── Simulate user activity (mouse movement every 5s) ─────────────────────────
if command -v xdotool &>/dev/null && [ -n "${DISPLAY:-}" ]; then
    (while true; do
        xdotool mousemove $((RANDOM % 1920)) $((RANDOM % 1080)) 2>/dev/null
        sleep 5
    done) &
    XDOTOOL_PID=$!
fi

# ── Determine execution method ────────────────────────────────────────────────
chmod +x "$SAMPLE" 2>/dev/null || true
FILE_TYPE=$(file "$SAMPLE" 2>/dev/null || echo "unknown")
EXEC_CMD=""

if   echo "$FILE_TYPE" | grep -qi "ELF";                    then EXEC_CMD="$SAMPLE"
elif echo "$FILE_TYPE" | grep -qi "Python script";           then EXEC_CMD="python3 $SAMPLE"
elif echo "$FILE_TYPE" | grep -qi "shell\|bash\|POSIX sh";  then EXEC_CMD="bash $SAMPLE"
elif echo "$FILE_TYPE" | grep -qi "Perl";                    then EXEC_CMD="perl $SAMPLE"
elif echo "$FILE_TYPE" | grep -qi "Ruby";                    then EXEC_CMD="ruby $SAMPLE"
elif echo "$FILE_TYPE" | grep -qi "PE\|MS-DOS\|Windows";    then
    if command -v wine &>/dev/null; then EXEC_CMD="wine $SAMPLE"
    else echo "PE_NO_WINE" > "$OUTPUT/exec_method.log"; fi
fi

echo "$FILE_TYPE"  > "$OUTPUT/file_type.log"
echo "$EXEC_CMD"  >> "$OUTPUT/exec_method.log"

# ── Execute with strace ───────────────────────────────────────────────────────
if [ -n "$EXEC_CMD" ]; then
    STRACE_CMD="strace -f -tt -T -s 256 \
        -e trace=process,file,network,memory,ipc,signal \
        -o $OUTPUT/strace.log \
        -- $EXEC_CMD"

    # Wrap with libfaketime if available
    if command -v faketime &>/dev/null; then
        STRACE_CMD="faketime '$FAKE_TIME' $STRACE_CMD"
    fi

    timeout "$TIMEOUT" bash -c "$STRACE_CMD" \
        > "$OUTPUT/stdout.log" 2> "$OUTPUT/stderr.log" || true
else
    echo "No execution method for: $FILE_TYPE" > "$OUTPUT/exec_error.log"
fi

# ── Post-execution: capture process snapshot ─────────────────────────────────
ps auxf > "$OUTPUT/processes.log" 2>/dev/null || true

# ── Capture memory maps of any survivors ─────────────────────────────────────
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    cat "/proc/$pid/maps" >> "$OUTPUT/mem_maps.log" 2>/dev/null || true
done

# ── Hash all newly dropped files ─────────────────────────────────────────────
find /tmp /home /root /var/tmp -newer "$SAMPLE" -type f 2>/dev/null \
    | grep -v "$SAMPLE" \
    | while read -r f; do
        sha256sum "$f" >> "$OUTPUT/dropped_hashes.log" 2>/dev/null || true
    done

# ── Cron / persistence checks ────────────────────────────────────────────────
crontab -l 2>/dev/null > "$OUTPUT/crontab.log" || true
ls -la /etc/cron* /var/spool/cron 2>/dev/null >> "$OUTPUT/crontab.log" || true
ls -la /etc/systemd/system/ 2>/dev/null > "$OUTPUT/systemd_units.log" || true
ls -la /etc/init.d/ 2>/dev/null >> "$OUTPUT/systemd_units.log" || true

# ── Network connections at time of termination ───────────────────────────────
ss -tunap 2>/dev/null > "$OUTPUT/network_state.log" || true
cat /etc/hosts > "$OUTPUT/hosts_file.log" 2>/dev/null || true

# ── Cleanup ───────────────────────────────────────────────────────────────────
kill ${INOTIFY_PID:-} ${TCPDUMP_PID:-} ${XDOTOOL_PID:-} 2>/dev/null || true
wait  ${INOTIFY_PID:-} ${TCPDUMP_PID:-} ${XDOTOOL_PID:-} 2>/dev/null || true

echo "done" > "$OUTPUT/status"
"""


class DynamicAnalyzer:

    def __init__(self):
        self._extractor = IOCExtractor()

    async def run(
        self,
        file_path:  str,
        file_name:  str,
        sha256:     str,
        timeout:    int = ANALYSIS_TIMEOUT,
        progress=None,
    ) -> Dict[str, Any]:
        try:
            import docker as docker_sdk  # type: ignore
            client = docker_sdk.from_env(timeout=10)
            client.ping()
        except Exception as exc:
            log.warning("Docker unavailable for dynamic analysis: %s", exc)
            return {"error": f"Docker not available: {exc}", "behavioral": []}

        return await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._run_sync(client, file_path, file_name, sha256, timeout, progress),
        )

    # ── Synchronous execution (runs in thread pool) ────────────────────────────

    def _run_sync(self, client, file_path, file_name, sha256, timeout, progress=None):
        import docker as docker_sdk

        result: Dict[str, Any] = {
            "executed":   False,
            "exec_method":"",
            "file_type":  "",
            "behavioral": [],
            "strace":     {},
            "pcap":       {},
            "fs_events":  {},
            "dropped_hashes": [],
            "persistence_checks": {},
            "anti_vm_attempts": [],
            "memory_anomalies": [],
        }

        # ── Ensure analysis image exists ──────────────────────────────────────
        try:
            client.images.get(ANALYSIS_IMAGE)
        except docker_sdk.errors.ImageNotFound:
            log.info("Building analysis image %s ...", ANALYSIS_IMAGE)
            try:
                _build_analysis_image(client)
            except Exception as exc:
                log.error("Failed to build analysis image %s: %s", ANALYSIS_IMAGE, exc, exc_info=True)
                result["error"] = f"Failed to build analysis image: {exc}"
                return result

        # ── Create isolated network ───────────────────────────────────────────
        net_name = f"sandbox-net-{sha256[:12]}"
        net = None
        try:
            net = client.networks.create(
                net_name,
                driver="bridge",
                internal=True,   # no external routing
                options={"com.docker.network.bridge.enable_ip_masquerade": "false"},
            )
        except Exception as exc:
            log.warning("Could not create isolated network: %s — using bridge", exc)

        container = None
        try:
            # ── Prepare analysis script ───────────────────────────────────────
            with tempfile.TemporaryDirectory() as tmpdir:
                script_path = os.path.join(tmpdir, "run_analysis.sh")
                with open(script_path, "w", newline="\n") as f:
                    f.write(_ANALYSIS_SH)

                # ── Launch container ──────────────────────────────────────────
                container = client.containers.run(
                    ANALYSIS_IMAGE,
                    command=["sleep", "infinity"],   # keep alive while we inject files
                    detach=True,
                    network=net_name if net else "bridge",
                    mem_limit="512m",
                    nano_cpus=1_000_000_000,         # 1 CPU
                    cap_add=["SYS_PTRACE"],           # needed for strace
                    security_opt=["seccomp=unconfined"],
                    environment={
                        "TERM": "xterm-256color",
                        "LANG": "en_US.UTF-8",
                    },
                    labels={"sandbox": "ti-platform", "sha256": sha256},
                    remove=False,
                    read_only=False,
                )

                # ── Copy sample and script into container ─────────────────────
                sample_arc   = _make_tar(file_path,   f"sample/{file_name}")
                script_arc   = _make_tar(script_path, "run_analysis.sh")
                container.put_archive("/", sample_arc)
                container.put_archive("/", script_arc)

                container.exec_run("chmod +x /run_analysis.sh")

                if progress:
                    progress.mark_done("sandbox_prep")
                    progress.mark_running("behavioral_exec")

                # ── Run analysis ──────────────────────────────────────────────
                exec_result = container.exec_run(
                    f"/run_analysis.sh /sample/{file_name} /output {timeout}",
                    workdir="/",
                    stream=False,
                    demux=False,
                )
                result["executed"] = True
                if progress:
                    progress.mark_running("time_manipulation")  # libfaketime active during exec

                # ── Wait for analysis script to finish (with outer timeout) ───
                deadline = timeout + 30
                import time
                start = time.time()
                while time.time() - start < deadline:
                    try:
                        status_bits, _ = container.exec_run(
                            "cat /output/status", demux=False
                        )
                        if b"done" in (status_bits or b""):
                            break
                    except Exception:
                        pass
                    time.sleep(3)

                # ── Collect artifacts ─────────────────────────────────────────
                if progress:
                    progress.mark_done("time_manipulation")
                    progress.mark_done("behavioral_exec")
                artifacts = _collect_artifacts(container, "/output")

            # ── Parse artifacts ───────────────────────────────────────────────
            strace_text = artifacts.get("strace.log", "")
            fs_text     = artifacts.get("fs_events.log", "")
            pcap_data   = artifacts.get("capture.pcap", b"") if isinstance(
                artifacts.get("capture.pcap"), bytes
            ) else b""
            hash_log    = artifacts.get("dropped_hashes.log", "")
            mem_maps    = artifacts.get("mem_maps.log", "")

            result["exec_method"] = artifacts.get("exec_method.log", "unknown").strip()
            result["file_type"]   = artifacts.get("file_type.log", "unknown").strip()

            if strace_text:
                result["strace"] = self._extractor.extract_from_strace(strace_text)
                result["behavioral"].extend(result["strace"].pop("behavioral", []))

            if pcap_data:
                result["pcap"] = self._extractor.extract_from_pcap(pcap_data)
                if result["pcap"].get("exfiltration_suspected"):
                    result["behavioral"].append({
                        "type": "exfiltration",
                        "description": f"Possible data exfiltration: {result['pcap']['bytes_sent']:,} bytes sent",
                        "severity": "critical",
                    })

            if fs_text:
                result["fs_events"] = self._extractor.extract_from_fs_events(fs_text)
                for pi in result["fs_events"].get("persistence_indicators", []):
                    result["behavioral"].append({
                        "type":        "persistence",
                        "description": pi["description"] + f" → {pi['path']}",
                        "severity":    "high",
                    })
                for ri in result["fs_events"].get("ransomware_indicators", []):
                    result["behavioral"].append({
                        "type":        "ransomware",
                        "description": ri["description"],
                        "severity":    "critical",
                    })

            if hash_log:
                result["dropped_hashes"] = self._extractor.extract_dropped_hashes(hash_log)

            # Memory anomaly: executable anonymous mappings
            if mem_maps:
                anon_exec = [l for l in mem_maps.splitlines()
                             if "rwxp" in l or "r-xp" in l and "[anon" in l]
                if anon_exec:
                    result["memory_anomalies"].append({
                        "type": "anon_exec",
                        "description": f"{len(anon_exec)} anonymous executable memory regions (shellcode/unpacking)",
                        "severity": "high",
                    })
                    result["behavioral"].extend(result["memory_anomalies"])

            # Persistence checks
            result["persistence_checks"] = {
                "cron":    artifacts.get("crontab.log", ""),
                "systemd": artifacts.get("systemd_units.log", ""),
            }

        except Exception as exc:
            log.error("Dynamic analysis error: %s", exc, exc_info=True)
            result["error"] = str(exc)

        finally:
            if container:
                try:
                    container.kill()
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if net:
                try:
                    net.remove()
                except Exception:
                    pass

        return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_tar(src_path: str, arc_name: str) -> bytes:
    """Create an in-memory tar archive containing a single file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(src_path, arcname=arc_name)
    return buf.getvalue()


def _collect_artifacts(container, output_dir: str) -> Dict[str, Any]:
    """Pull all files from the container's output directory."""
    artifacts: Dict[str, Any] = {}
    try:
        raw, _ = container.get_archive(output_dir)
        buf = io.BytesIO(b"".join(raw))
        with tarfile.open(fileobj=buf) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = os.path.basename(member.name)
                f    = tar.extractfile(member)
                if f is None:
                    continue
                data = f.read()
                # Store text files as strings, binary (pcap) as bytes
                if name.endswith(".pcap"):
                    artifacts[name] = data
                else:
                    artifacts[name] = data.decode("utf-8", errors="replace")
    except Exception as exc:
        log.warning("Failed to collect artifacts: %s", exc)
    return artifacts


def _build_analysis_image(client):
    """Build the analysis container image on first use."""
    dockerfile = b"""
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        strace tcpdump inotify-tools libfaketime \
        python3 python3-pip perl ruby \
        curl wget net-tools iproute2 procps \
        file binutils xdotool \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m analyst
WORKDIR /
CMD ["sleep", "infinity"]
"""
    client.images.build(
        fileobj=io.BytesIO(dockerfile),
        tag=ANALYSIS_IMAGE,
        rm=True,
    )
    log.info("Analysis image built: %s", ANALYSIS_IMAGE)
