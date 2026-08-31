"""
Containment Agent — ações defensivas locais (lab Ubuntu).
Bloqueio/desbloqueio de IP via ufw, com whitelist e dry-run.
"""
from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# IPs que NUNCA devem ser bloqueados
DEFAULT_WHITELIST = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

LOG_PATH = Path("reports") / "containment_actions.log"


@dataclass
class ContainmentResult:
    success: bool
    action: str
    target: str
    message: str
    dry_run: bool = False


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_whitelisted(ip: str, extra: set[str] | None = None) -> bool:
    blocked = set(DEFAULT_WHITELIST)
    if extra:
        blocked |= extra
    if ip in blocked:
        return True
    # redes privadas comuns no lab — não bloqueia a própria LAN por engano
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private and str(addr) in {"10.0.2.2", "10.0.2.15"}:
            return True
    except ValueError:
        pass
    return False


def _run(cmd: list[str], dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, f"[dry-run] {' '.join(cmd)}"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            return False, err or out or f"exit {proc.returncode}"
        return True, out or "ok"
    except FileNotFoundError:
        return False, "ufw não encontrado. Rode no Ubuntu com ufw instalado."
    except Exception as e:
        return False, str(e)


def drop_ssh_from_ip(ip: str) -> str:
    notes = []
    for cmd in (
        ["sudo", "-n", "ss", "-K", "dst", ip, "dport", "22"],
        ["sudo", "-n", "pkill", "-f", f"sshd:.*{ip}"],
    ):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            extra = ((proc.stdout or "") + (proc.stderr or "")).strip()
            notes.append(extra or f"{' '.join(cmd)} exit {proc.returncode}")
        except Exception as e:
            notes.append(str(e))
    return " | ".join(notes)


def _log(action: str, target: str, message: str, dry_run: bool) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    mode = "DRY-RUN" if dry_run else "LIVE"
    line = f"{ts} | {mode} | {action} | {target} | {message}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)


def block_ip(ip: str, dry_run: bool = True, extra_whitelist: set[str] | None = None) -> ContainmentResult:
    ip = ip.strip()
    if not _valid_ip(ip):
        return ContainmentResult(False, "block", ip, "IP inválido")
    if _is_whitelisted(ip, extra_whitelist):
        return ContainmentResult(False, "block", ip, "IP na whitelist — bloqueio recusado", dry_run=dry_run)
    # ufw deny from <ip>
    ok, msg = _run(["sudo", "ufw", "deny", "from", ip], dry_run)
    if ok and not dry_run:
        drop = drop_ssh_from_ip(ip)
        msg = f"{msg} | {drop}"
    _log("block", ip, msg, dry_run)
    return ContainmentResult(ok, "block", ip, msg, dry_run=dry_run)

def unblock_ip(ip: str, dry_run: bool = True) -> ContainmentResult:
    ip = ip.strip()
    if not _valid_ip(ip):
        return ContainmentResult(False, "unblock", ip, "IP inválido")

    ok, msg = _run(["sudo", "ufw", "delete", "deny", "from", ip], dry_run)
    _log("unblock", ip, msg, dry_run)
    return ContainmentResult(ok, "unblock", ip, msg, dry_run=dry_run)


def status() -> str:
    ok, msg = _run(["sudo", "ufw", "status", "numbered"], dry_run=False)
    return msg if ok else f"erro: {msg}"