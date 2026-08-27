"""
SOC AI Analyst — API (Fase 4)
Rode: uvicorn api:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from config import settings
from ai_analyst import AIAnalyst
from mock_splunk_client import MockSplunkClient
from local_log_client import LocalLogClient
from containment import block_ip, unblock_ip, status as ufw_rules
from session_watch import list_ssh_sessions, find_foreign_sessions, watch_once
from geo import locate_many
from sec_tools import host_defense_snapshot

app = FastAPI(title="SOC AI Analyst", version="4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND = Path(__file__).parent / "frontend"
LAST = {"results": [], "ips": [], "markers": []}


class TriageIn(BaseModel):
    source: str = "local"
    count: int = 5


class InvestigateIn(BaseModel):
    source: str = "local"
    host: str | None = None
    user: str | None = None


class ContainIn(BaseModel):
    ip: str
    action: str = "block"
    execute: bool = False


class WatchIn(BaseModel):
    block: bool = False
    execute: bool = False


def get_client(source: str):
    source = (source or "local").lower()
    if source == "mock":
        return MockSplunkClient(), "DADOS SIMULADOS (mock)"
    if source == "windows":
        from windows_log_client import WindowsLogClient
        return WindowsLogClient(), "Windows Security Event Log"
    if source == "splunk":
        from splunk_client import SplunkClient
        return SplunkClient(settings.splunk), "Splunk real"
    return LocalLogClient(), "LOGS LOCAIS (auth.log)"


def result_to_dict(r) -> dict:
    if is_dataclass(r):
        d = asdict(r)
    elif hasattr(r, "__dict__"):
        d = dict(r.__dict__)
    else:
        d = {"summary": str(r)}
    d.pop("raw_alert", None)
    return d


def pull_ips(results) -> list[str]:
    found = []
    for r in results:
        blob = " ".join(str(x) for x in (
            getattr(r, "summary", ""),
            getattr(r, "indicators", "") or "",
            getattr(r, "raw_alert", "") or "",
        ))
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
            found.append(m)
    return list(dict.fromkeys(found))


@app.get("/api/health")
def health():
    return {"ok": True, "service": "soc-ai-analyst"}


@app.post("/api/triage")
def api_triage(body: TriageIn):
    try:
        client, fonte = get_client(body.source)
        analyst = AIAnalyst(settings.groq)
        alerts = client.get_alerts(count=max(1, min(body.count, 20)))
        results = [analyst.triage_alert(a) for a in alerts]
        ips = pull_ips(results)
        markers = locate_many(ips)
        payload = [result_to_dict(r) for r in results]
        LAST["results"] = payload
        LAST["ips"] = ips
        LAST["markers"] = markers
        return {
            "fonte": fonte,
            "count": len(payload),
            "results": payload,
            "ips": ips,
            "markers": markers,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigate")
def api_investigate(body: InvestigateIn):
    if not body.host and not body.user:
        raise HTTPException(status_code=400, detail="Informe host ou user")
    try:
        client, fonte = get_client(body.source)
        analyst = AIAnalyst(settings.groq)
        alert = {"host": body.host, "user": body.user, "note": "API"}
        ctx = client.get_context_for_event(host=body.host, user=body.user)
        md = analyst.investigate_incident(alert, ctx)
        return {"fonte": fonte, "report": md, "context_events": len(ctx)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions")
def api_sessions():
    all_s = [{"user": s.user, "ip": s.ip, "tty": s.tty} for s in list_ssh_sessions()]
    foreign = [{"user": s.user, "ip": s.ip, "tty": s.tty} for s in find_foreign_sessions()]
    return {"sessions": all_s, "foreign": foreign}


@app.post("/api/watch")
def api_watch(body: WatchIn):
    dry = not body.execute
    rows = watch_once(dry_run=dry, auto_block=body.block)
    return {"results": rows, "dry_run": dry}


@app.post("/api/contain")
def api_contain(body: ContainIn):
    dry = not body.execute
    if body.action == "unblock":
        r = unblock_ip(body.ip.strip(), dry_run=dry)
    else:
        r = block_ip(body.ip.strip(), dry_run=dry)
    return {
        "success": r.success,
        "dry_run": r.dry_run,
        "target": r.target,
        "message": r.message,
    }


@app.get("/api/defense")
def api_defense():
    snap = host_defense_snapshot()
    snap["ufw_rules"] = ufw_rules()
    snap["last_ips"] = LAST.get("ips", [])
    snap["markers"] = LAST.get("markers", [])
    return snap


@app.get("/")
def index():
    index = FRONTEND / "index.html"
    if not index.exists():
        return {"ok": True, "hint": "frontend/index.html ausente"}
    return FileResponse(index)


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")