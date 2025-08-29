# app.py
import json, os, datetime, subprocess, shutil, html
from pathlib import Path
from collections import deque
from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ----------------- Config -----------------
OUTPUT_ROOT = Path("/var/lib/soar/prowler")   # where we store scan results
OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

# Local secret files (on the same machine)
AWS_ENV_FILE  = "/etc/soar/aws"   # AWS_ACCESS_KEY_ID=..., AWS_SECRET_ACCESS_KEY=..., AWS_DEFAULT_REGION=..., (opt) AWS_SESSION_TOKEN=...
AZURE_ENV_FILE = "/etc/soar/azure" # tenant_id=..., client_id=..., client_secret=..., subscription_id=...

# (Optional) Vault fallback (kept for compatibility; not required)
VAULT_ADDR  = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_MOUNT = "soar"
_vault_client = None
def _vault_ready(): return bool(VAULT_ADDR and VAULT_TOKEN)
def vget(path: str) -> dict:
    """Read a dict from Vault KV v2 at soar/<path>. Returns {} if not present/available."""
    global _vault_client
    if not _vault_ready():
        return {}
    try:
        import hvac
        if _vault_client is None:
            _vault_client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
        res = _vault_client.secrets.kv.v2.read_secret_version(mount_point=VAULT_MOUNT, path=path)
        return res["data"]["data"] or {}
    except Exception as e:
        print({"vault": "read_error", "path": path, "err": str(e)})
        return {}

app = FastAPI()
ALERT_LOG = deque(maxlen=100)  # newest first

# Serve scan artifacts directly
app.mount("/artifacts", StaticFiles(directory=str(OUTPUT_ROOT), html=True), name="artifacts")

# ---------- Helpers ----------
def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

def load_kv_file(path: str) -> dict:
    """Parse KEY=VALUE lines (VALUE may be quoted)."""
    out = {}
    p = Path(path)
    if not p.exists():
        return out
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        out[k] = v
    return out

def get_aws_creds() -> dict:
    """Read AWS creds from /etc/soar/aws (preferred), optional Vault fallback."""
    d = load_kv_file(AWS_ENV_FILE)
    if d:
        return {
            "access_key": d.get("AWS_ACCESS_KEY_ID", ""),
            "secret_key": d.get("AWS_SECRET_ACCESS_KEY", ""),
            "session_token": d.get("AWS_SESSION_TOKEN", ""),
            "region": d.get("AWS_DEFAULT_REGION", "us-east-1"),
            "source": f"file:{AWS_ENV_FILE}",
        }
    kv = vget("aws/default")
    if kv:
        return {
            "access_key": kv.get("access_key", ""),
            "secret_key": kv.get("secret_key", ""),
            "session_token": kv.get("session_token", ""),
            "region": kv.get("region", "us-east-1"),
            "source": "kv:soar/aws/default",
        }
    return {"access_key":"", "secret_key":"", "session_token":"", "region":"us-east-1", "source":"none"}

def get_azure_creds() -> dict:
    """Read Azure creds from /etc/soar/azure."""
    d = load_kv_file(AZURE_ENV_FILE)
    return {
        "tenant_id": d.get("tenant_id", ""),
        "client_id": d.get("client_id", ""),
        "client_secret": d.get("client_secret", ""),
        "subscription_id": d.get("subscription_id", ""),
        "source": f"file:{AZURE_ENV_FILE}" if d else "none",
    }

# ---------- Normalizer ----------
def normalize_splunk(payload: dict) -> dict:
    """
    Flatten Splunk payload and then FORCE:
      type="Domain Compromise"
      clouds=["onprem","azure"]
    """
    flat = dict(payload)
    result = payload.get("result") or {}

    norm = {
        "alert_id": flat.get("alert_id") or flat.get("sid") or flat.get("_sid") or "no-alert-id",
        "search_name": flat.get("search_name") or flat.get("savedsearch_name") or "",
        "app": flat.get("app"),
        "owner": flat.get("owner"),
        "results_link": flat.get("results_link"),
        "received_at": now_iso(),

        # Common fields (if present)
        "host": result.get("ComputerName") or flat.get("host"),
        "source_ip": result.get("SourceIp") or flat.get("source_ip"),
        "source_port": result.get("SourcePort") or flat.get("source_port"),
        "dest_ip": result.get("DestinationIp") or flat.get("dest_ip"),
        "dest_port": result.get("DestinationPort") or flat.get("dest_port"),
        "protocol": result.get("Protocol") or flat.get("protocol"),

        # Optional identity/cloud hints
        "user_upn": result.get("user_upn") or flat.get("user_upn"),
        "onprem_sam": result.get("sam") or flat.get("onprem_sam"),
        "aws_account_id": result.get("aws_account_id") or flat.get("aws_account_id"),
        "aws_instance_id": result.get("aws_instance_id") or flat.get("aws_instance_id"),
        "region": result.get("region") or flat.get("region"),
    }

    # Force your policy for every alert
    norm["type"] = "Domain Compromise"
    norm["clouds"] = ["onprem", "azure"]
    return norm

# ---------- Router / Playbook (containment simulated) ----------
def route_event(evt: dict):
    return playbook_domain_compromise(evt)

def playbook_domain_compromise(evt: dict):
    actions = []
    actions.append({"actor": "ad",    "action": "disable_user",           "sam": evt.get("onprem_sam") or "<unknown>",    "status": "simulated"})
    actions.append({"actor": "azure", "action": "revoke_signin_sessions", "user_upn": evt.get("user_upn") or "<unknown>", "status": "simulated"})
    if evt.get("aws_instance_id"):
        actions.append({"actor": "aws", "action": "snapshot_and_quarantine", "instance_id": evt["aws_instance_id"], "status": "simulated"})
    return {"routed": True, "playbook": "domain_compromise", "actions": actions}

# ---------- Prowler runners ----------
def _prowler_cmd_candidates(base_cmd: list[str], formats: str, outdir: Path) -> list[list[str]]:
    """Return CLI variants for v3 (preferred) and older syntaxes."""
    return [
        base_cmd + ["--output-formats", formats, "--output-directory", str(outdir)],  # v3
        base_cmd + ["-M", formats, "--output-directory", str(outdir)],               # v2/v3 short
        base_cmd + ["--output", formats, "--output-directory", str(outdir)],         # legacy scripts
    ]

def _launch(cmd, env, cwd: Path, log_path: Path):
    cwd.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab", buffering=0) as log:
        log.write(f"[{now_iso()}] CMD: {' '.join(cmd)}\n".encode())
    try:
        return subprocess.Popen(
            cmd, env=env, cwd=str(cwd),
            stdout=open(log_path, "ab", buffering=0),
            stderr=open(log_path, "ab", buffering=0),
        )
    except Exception as e:
        with open(log_path, "ab", buffering=0) as log:
            log.write(f"[{now_iso()}] ERROR: {e}\n".encode())
        return None

def prowler_scan_aws(alert_id: str, region_hint: str | None):
    creds = get_aws_creds()
    region = (region_hint or creds["region"] or "us-east-1").strip()
    outdir = OUTPUT_ROOT / alert_id / "aws"
    env = os.environ.copy()
    if creds["access_key"]:    env["AWS_ACCESS_KEY_ID"]     = creds["access_key"]
    if creds["secret_key"]:    env["AWS_SECRET_ACCESS_KEY"] = creds["secret_key"]
    if creds["session_token"]: env["AWS_SESSION_TOKEN"]     = creds["session_token"]
    env["AWS_DEFAULT_REGION"] = region

    base = ["prowler", "aws"] if shutil.which("prowler") else ["python3", "/home/ubuntu/prowler/prowler-cli.py", "aws"]
    candidates = _prowler_cmd_candidates(base, "html,csv,json-asff", outdir)

    started = False
    for cmd in candidates:
        proc = _launch(cmd, env, outdir, outdir / "scan_aws.log")
        if proc:
            started = True
            break

    print({"prowler": "aws_started" if started else "aws_not_started", "region": region, "alert_id": alert_id})
    return started

def prowler_scan_azure(alert_id: str):
    az = get_azure_creds()
    if not (az["tenant_id"] and az["client_id"] and az["client_secret"] and az["subscription_id"]):
        print({"prowler": "azure_skipped_missing_creds", "alert_id": alert_id})
        return False

    outdir = OUTPUT_ROOT / alert_id / "azure"
    env = os.environ.copy()
    env["AZURE_TENANT_ID"]       = az["tenant_id"]
    env["AZURE_CLIENT_ID"]       = az["client_id"]
    env["AZURE_CLIENT_SECRET"]   = az["client_secret"]
    env["AZURE_SUBSCRIPTION_ID"] = az["subscription_id"]

    base = ["prowler", "azure"] if shutil.which("prowler") else ["python3", "/home/ubuntu/prowler/prowler-cli.py", "azure"]
    candidates = _prowler_cmd_candidates(base, "html,csv,json", outdir)

    started = False
    for cmd in candidates:
        proc = _launch(cmd, env, outdir, outdir / "scan_azure.log")
        if proc:
            started = True
            break

    print({"prowler": "azure_started" if started else "azure_not_started", "alert_id": alert_id})
    return started

def build_scan_index(alert_id: str):
    base = OUTPUT_ROOT / alert_id

    def list_items(folder: str, started: bool):
        p = base / folder
        items = []
        if p.exists():
            for ext in ("*.html", "*.csv", "*.json", "*.log"):
                for f in sorted(p.glob(ext)):
                    items.append(f'<li><a href="{html.escape(folder)}/{html.escape(f.name)}" target="_blank">{html.escape(f.name)}</a></li>')
        if not items:
            msg = "Scan started; files will appear here when ready." if started else "Scan not started (missing tool or creds)."
            items = [f"<li><em>{msg}</em></li>"]
        return "\n".join(items)

    started_aws   = (base / "aws" / "scan_aws.log").exists()
    started_azure = (base / "azure" / "scan_azure.log").exists()

    try:
        alert_json_text = (base / "alert.json").read_text()
    except Exception:
        alert_json_text = "{}"

    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>Scan artifacts — {html.escape(alert_id)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding:16px; }}
    pre {{ background:#0b1020; color:#e9edf1; padding:16px; border-radius:8px; overflow:auto; }}
    h2 {{ margin-top: 24px; }}
  </style>
</head>
<body>
  <h1>Scan artifacts for <code>{html.escape(alert_id)}</code></h1>
  <h2>AWS</h2>
  <ul>{list_items('aws', started_aws)}</ul>
  <h2>Azure</h2>
  <ul>{list_items('azure', started_azure)}</ul>
  <h3>Full normalized alert</h3>
  <pre>{html.escape(alert_json_text)}</pre>
</body>
</html>"""
    (base / "index.html").write_text(page, encoding="utf-8")

# ---------- Ingestion ----------
async def _ingest(request: Request, bg: BackgroundTasks):
    # Accept JSON, form, or raw
    try:
        data = await request.json()
    except Exception:
        try:
            form = await request.form()
            data = dict(form)
        except Exception:
            raw = await request.body()
            try:
                data = json.loads(raw.decode("utf-8", errors="ignore"))
            except Exception:
                data = {"_raw": raw.decode("utf-8", errors="ignore")}

    alert_id = data.get("alert_id") or data.get("sid") or data.get("_sid") or "no-alert-id"
    print({"received_from": "splunk", "alert_id": alert_id})

    def process():
        evt = normalize_splunk(data)

        # Persist normalized alert for the artifact page
        base = OUTPUT_ROOT / evt["alert_id"]
        base.mkdir(parents=True, exist_ok=True)
        (base / "alert.json").write_text(json.dumps(evt, indent=2), encoding="utf-8")

        # Route playbook (simulated containment)
        result = route_event(evt)

        # Trigger CSPM scans (AWS always, Azure if creds ready)
        started_aws   = prowler_scan_aws(evt["alert_id"], region_hint=evt.get("region"))
        started_azure = prowler_scan_azure(evt["alert_id"])

        # Build/refresh the artifact index page
        build_scan_index(evt["alert_id"])

        # Add to in-memory dashboard
        ALERT_LOG.appendleft({
            "at": now_iso(),
            "alert_id": evt["alert_id"],
            "search_name": evt.get("search_name"),
            "type": evt.get("type"),
            "clouds": evt.get("clouds"),
            "host": evt.get("host"),
            "source_ip": evt.get("source_ip"),
            "dest_ip": evt.get("dest_ip"),
            "results_link": evt.get("results_link"),
            "scan_url": f"/artifacts/{evt['alert_id']}/index.html",
            "result": result,
        })
        print({"router_result": result, "alert_id": evt["alert_id"], "scans": {"aws": started_aws, "azure": started_azure}})

    bg.add_task(process)
    return {"accepted": True, "alert_id": alert_id}

# ---------- GUI & API ----------
@app.get("/")
def root_redirect():
    return RedirectResponse(url="/dashboard", status_code=302)

@app.post("/")
async def root_post(request: Request, bg: BackgroundTasks):
    return await _ingest(request, bg)

@app.post("/webhooks/splunk")
async def splunk_post(request: Request, bg: BackgroundTasks):
    return await _ingest(request, bg)

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    rows = []
    for rec in list(ALERT_LOG):
        actions = rec["result"].get("actions") or []
        actions_html = "".join(
            f"<li><code>{a.get('actor')}</code>: {a.get('action')} "
            f"{'('+a.get('status')+')' if a.get('status') else ''}</li>"
            for a in actions
        )
        search_link = f'<a href="{rec.get("results_link")}" target="_blank">search</a>' if rec.get("results_link") else "-"
        scan_link   = f'<a href="{rec.get("scan_url")}" target="_blank">scan</a>'
        rows.append(f"""
        <tr>
            <td>{rec.get('at')}</td>
            <td style="max-width:260px;word-break:break-all">{rec.get('alert_id')}</td>
            <td>{rec.get('search_name') or '-'}</td>
            <td>{rec.get('type') or '-'}</td>
            <td>{', '.join(rec.get('clouds') or []) or '-'}</td>
            <td>{rec.get('host') or '-'}</td>
            <td>{rec.get('source_ip') or '-'}</td>
            <td>{rec.get('dest_ip') or '-'}</td>
            <td>{search_link} &nbsp;|&nbsp; {scan_link}</td>
            <td><ul style="margin:0;padding-left:18px">{actions_html or '<em>none</em>'}</ul></td>
        </tr>
        """)

    html_doc = f"""
<!doctype html>
<html>
<head>
  <meta http-equiv="refresh" content="5">
  <title>SOAR Alert Dashboard</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding:16px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; }}
    th {{ background: #f4f6f8; position: sticky; top: 0; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    code {{ background: #f1f1f1; padding: 1px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>SOAR Alert Dashboard</h1>
  <p>Auto-refreshing every 5s. Total in memory: {len(ALERT_LOG)}</p>
  <p>API: <a href="/api/events">/api/events</a></p>
  <table>
    <thead>
      <tr>
        <th>Received</th><th>Alert ID</th><th>Search</th><th>Type</th>
        <th>Clouds</th><th>Host</th><th>Src IP</th><th>Dst IP</th><th>Links</th><th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="10" style="text-align:center;padding:24px"><em>No events yet</em></td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""
    return HTMLResponse(content=html_doc, status_code=200)

@app.get("/api/events")
def api_events():
    return JSONResponse([{
        k: rec[k] for k in (
            "at","alert_id","search_name","type","clouds","host",
            "source_ip","dest_ip","results_link","scan_url","result"
        )
    } for rec in list(ALERT_LOG)])
