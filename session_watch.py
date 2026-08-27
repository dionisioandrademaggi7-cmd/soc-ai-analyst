"""
Monitor de sessoes SSH vs whitelist.
Lab: alerta IPs remotos que nao estao na lista segura.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

DEFAULT_WHITELIST = {
    "127.0.0.1",
    "::1",
    "local",
}


@dataclass
class SessionHit:
    user: str
    ip: str
    tty: str


def _run(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return str(e)


def list_ssh_sessions() -> list[SessionHit]:
    hits: list[SessionHit] = []
    who = _run(["who"])
    for line in who.splitlines():
        m = re.search(
            r"^(\S+)\s+(\S+)\s+.*?(\d{1,3}(?:\.\d{1,3}){3})",
            line,
        )
        if m:
            hits.append(SessionHit(user=m.group(1), ip=m.group(3), tty=m.group(2)))
            continue
        parts = line.split()
        if len(parts) >= 2:
            hits.append(SessionHit(user=parts[0], ip="local", tty=parts[1]))
    return hits


def find_foreign_sessions(whitelist: set[str] | None = None) -> list[SessionHit]:
    wl = set(DEFAULT_WHITELIST)
    if whitelist:
        wl |= set(whitelist)
    return [s for s in list_ssh_sessions() if s.ip not in wl]


def watch_once(dry_run: bool = True, auto_block: bool = False) -> list[dict]:
    from containment import block_ip

    foreign = find_foreign_sessions()
    results = []
    for s in foreign:
        block_msg = None
        action = "alert"
        if auto_block and s.ip not in DEFAULT_WHITELIST:
            r = block_ip(s.ip, dry_run=dry_run)
            action = "block"
            block_msg = r.message
        row = {
            "user": s.user,
            "ip": s.ip,
            "tty": s.tty,
            "action": action,
            "block": block_msg,
            "dry_run": dry_run,
        }
        results.append(row)
        extra = f" | contain: {block_msg}" if block_msg else ""
        print(f"[!] Sessao suspeita: user={s.user} ip={s.ip} tty={s.tty}{extra}")
    if not results:
        print("[*] Nenhuma sessao fora da whitelist.")
    return results