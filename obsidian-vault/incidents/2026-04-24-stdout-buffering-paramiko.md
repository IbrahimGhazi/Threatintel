# 2026-04-24 — `python` stdout block-buffering hid hang

**Severity:** sev3 (debugging delay, no production impact)
**Detected:** Background-launched `deploy_m3_embeddings.py` showed 0 bytes of output for 7+ minutes. Initial guess: paramiko hung.
**Resolved:** Relaunched with `python -u`. Output appeared immediately; revealed the *actual* hang was the [[incidents/2026-04-24-ti-platform-secret-misreference|secret misreference]].
**Root cause:** When Python's stdout is redirected to a non-tty (e.g. background task output file on Windows), it switches from line-buffered to block-buffered. `print()` calls accumulate until buffer fills (~8 KB). `sys.stdout.reconfigure(encoding=...)` does NOT change buffering.
**Fix:** Always pass `-u` (or set `PYTHONUNBUFFERED=1`) when launching Python scripts in background.
**Followups:**
- ✅ Added to [[runbooks/connect-server-vm]] under "When running long scripts in background"
- ✅ All future deploy orchestrators use `python -u`
