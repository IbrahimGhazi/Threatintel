# Connect to Server VM #runbook

> **Credentials:** never check secrets into the vault. Pull from your local `.env`, password manager, or k8s secret. Examples below use `${...}` placeholders — set those in your shell before running.

## Direct SSH

```sh
ssh tiuser@192.168.3.210
# password: ${VM_SSH_PASS}
```

## From Python (paramiko, Windows)

Windows occasionally throws `socket.gaierror 10109` even with numeric IPs. Fix: force `AF_INET` in `socket.getaddrinfo` BEFORE importing paramiko.

```python
import os, socket
_og = socket.getaddrinfo
def _v4(h, p, f=0, t=0, pr=0, fl=0):
    return _og(h, p, socket.AF_INET, t, pr, fl)
socket.getaddrinfo = _v4

import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.3.210",
          username="tiuser",
          password=os.environ["VM_SSH_PASS"],   # never hard-code
          timeout=30)
```

⚠️ Match paramiko's positional call shape exactly — using `**kwargs` triggers `got multiple values for argument 'family'`.

## When running long scripts in background

Always `python -u` — without it, stdout block-buffers when redirected and you'll see 0 bytes for minutes while paramiko works. We've been bitten by this. See [[incidents/README]] when adding case studies.

## Helper: psql via kubectl exec

```python
import os, base64
def psql(c, sql, pretty=False):
    b = base64.b64encode(sql.encode("utf-8")).decode("ascii")
    flags = "" if pretty else "-A -F'|'"
    pg_pw = os.environ["PG_PASSWORD"]              # from your secret store
    cmd = ("kubectl -n ti exec ti-postgresql-0 -- sh -c "
           f"\"echo {b} | base64 -d | "
           f"PGPASSWORD={pg_pw} "
           f"psql -U tiplatform -d tiplatform {flags}\"")
    _, o, e = c.exec_command(cmd, timeout=120)
    return o.read().decode("utf-8", "replace"), e.read().decode("utf-8", "replace")
```

Base64 encoding the SQL avoids quoting hell with quotes/newlines/JSON inside SQL.

## Suggested `.env` for local ops scripts

```
VM_SSH_PASS=...
PG_PASSWORD=...
```

Then `source .env` (or use `python-dotenv`) before running.
