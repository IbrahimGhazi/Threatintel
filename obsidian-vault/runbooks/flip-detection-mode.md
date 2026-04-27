# Flip Reputation Detection Mode #runbook

Modes: `off` / `shadow` / `enforce`. Hot-reloaded every 60s — no redeploy needed.

> **Credentials:** never check secrets into the vault. Set `VM_SSH_PASS` and `PG_PASSWORD` in your local `.env` (or shell) before running. See [[runbooks/connect-server-vm]] for the standard env-var pattern.

## Flip to enforce

```sh
python -u -c "
import os, socket
_og = socket.getaddrinfo
def _v4(h,p,f=0,t=0,pr=0,fl=0): return _og(h,p,socket.AF_INET,t,pr,fl)
socket.getaddrinfo = _v4
import paramiko, base64, time
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.3.210', username='tiuser',
          password=os.environ['VM_SSH_PASS'], timeout=20)

PG_PW = os.environ['PG_PASSWORD']
sql=\"UPDATE platform_settings SET value='enforce' WHERE key='reputation_detection_mode';\"
b=base64.b64encode(sql.encode()).decode()
cmd=f'kubectl -n ti exec ti-postgresql-0 -- sh -c \"echo {b} | base64 -d | PGPASSWORD={PG_PW} psql -U tiplatform -d tiplatform\"'
_,o,e=c.exec_command(cmd,timeout=30); print(o.read().decode())
print('Sleeping 75s for hot reload...'); time.sleep(75)

# Verify
_,o,_=c.exec_command('kubectl -n ti logs deploy/ti-correlation --tail=50 | grep \"Reputation detection mode\" | tail -3', timeout=30)
print(o.read().decode())
c.close()
"
```

## Flip to shadow (rollback)

Same script, change `'enforce'` → `'shadow'`.

## Flip to off (full disable)

Same script, change to `'off'`. Scorer still constructs but bypasses everything.

## Verification SQL

```sql
-- Did the flip stick?
SELECT key, value, updated_at FROM platform_settings WHERE key='reputation_detection_mode';

-- Are events still being scored?
SELECT COUNT(*) FROM reputation_shadow_events WHERE created_at > NOW() - INTERVAL '3 minutes';

-- Pre/post comparison
SELECT rule_name,
       COUNT(*) FILTER (WHERE would_fire) AS would_fire,
       COUNT(*) AS total
FROM reputation_shadow_events
WHERE created_at > NOW() - INTERVAL '15 minutes'
GROUP BY rule_name;
```

## See also
- [[milestones/M2-enforce]] for the production flip context + 24h baseline
- [[architecture/schema]] for `reputation_shadow_events` shape
