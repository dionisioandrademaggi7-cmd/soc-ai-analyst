"""
Motor de alerta autónomo.

Vigia auth.log (ou journalctl / Windows) e dispara SOZINHO em cada evento
novo de autenticação (FAIL, INVALID, LOGIN, SUDO, SESSION, SSH) — sem o
operador puxar triagem nem o CLI. Rajada (BURST) é extra, às 5 falhas/120s.
Containment só com auto_block e dry-run por omissão.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from session_watch import DEFAULT_WHITELIST as SESSION_WHITELIST
from containment import block_ip, DEFAULT_WHITELIST as CONTAIN_WHITELIST

RE_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
# Qualquer evento de autenticação / sshd / sudo — não só Failed/Accepted
RE_EVENT = re.compile(
    r"(Failed password|Failed publickey|Invalid user|authentication failure|"
    r"Accepted password|Accepted publickey|maximum authentication|"
    r"Too many authentication|sudo:|session opened|session closed|"
    r"Disconnected from|Connection closed|sshd\[)",
    re.I,
)

AUTH_CANDIDATES = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
]

LAB_NEVER_BLOCK = {"10.0.2.2", "10.0.2.15"}

MAX_ALERTS = 50
POLL_SEC = 2.0


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


FAIL_THRESHOLD = _env_int("SOC_FAIL_THRESHOLD", 5)
WINDOW_SEC = _env_int("SOC_WINDOW_SEC", 120)
COOLDOWN_SEC = _env_int("SOC_COOLDOWN_SEC", 60)

_lock = threading.RLock()
_alerts: deque[dict] = deque(maxlen=MAX_ALERTS)
_fail_times: dict[str, deque] = defaultdict(deque)
_cooldown_until: dict[tuple[str, str], float] = {}
_thread: threading.Thread | None = None
_stop = threading.Event()
_running = False
_source = "—"
_hint = ""
_auto_block = False
_execute = False
_journal_proc: subprocess.Popen | None = None


def _never_block(ip: str) -> bool:
    if ip in SESSION_WHITELIST or ip in CONTAIN_WHITELIST or ip in LAB_NEVER_BLOCK:
        return True
    return False


def _is_whitelisted(ip: str) -> bool:
    return ip in SESSION_WHITELIST


def find_auth() -> Path | None:
    for p in AUTH_CANDIDATES:
        if p.exists():
            try:
                with p.open("r"):
                    return p
            except PermissionError:
                continue
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prune_fails(ip: str, now: float) -> int:
    dq = _fail_times[ip]
    cutoff = now - WINDOW_SEC
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)


def _in_cooldown(ip: str, kind: str) -> bool:
    until = _cooldown_until.get((ip, kind), 0.0)
    return time.time() < until


def _arm_cooldown(ip: str, kind: str) -> None:
    _cooldown_until[(ip, kind)] = time.time() + COOLDOWN_SEC


def _next_step(kind: str, ip: str) -> str:
    base = (
        f"Abra o SOC AI Analyst (Triagem / Investigar) para o relatório detalhado. "
        f"IP={ip}."
    )
    if kind == "LOGIN":
        return base + " Validar se o logon é legítimo; se for suspeito, Contain (Executar block)."
    if kind == "BURST":
        return base + " Rajada de falhas — confirmar brute-force; se for suspeito, Contain (Executar block)."
    if kind in ("FAIL", "INVALID"):
        return base + " Tentativa de logon recusada. Continua a vigiar; use Triagem para o relatório."
    if kind == "SUDO":
        return base + " Evento sudo — confirmar se a elevação de privilégio é esperada."
    if kind == "SESSION":
        return base + " Sessão aberta/fechada. Confirmar se o utilizador é esperado."
    return base


def _notify(rec: dict) -> None:
    """Som + banner independentes. Nunca rebenta o watcher."""
    kind = rec.get("kind", "?")
    ip = rec.get("ip", "?")
    title = f"SOC ALERTA {kind}"
    body = rec.get("next_step") or f"IP={ip}"
    banner = (
        "\n"
        + "=" * 72
        + f"\n*** ALERTA AUTÓNOMO SOC  [{kind}]  ip={ip}  ***\n"
        + f"{body}\n"
        + (f"contain: {rec['contain_result']}\n" if rec.get("contain_result") else "")
        + "=" * 72
        + "\n"
    )
    try:
        sys.stdout.write("\a")
        sys.stdout.write(banner)
        sys.stdout.flush()
    except Exception:
        pass

    if os.name != "nt":
        try:
            if shutil.which("notify-send"):
                subprocess.run(
                    ["notify-send", "-u", "critical", title, body[:200]],
                    timeout=5,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        except Exception:
            pass
        return

    try:
        import winsound

        winsound.Beep(1000, 400)
    except Exception:
        pass
    try:
        safe_title = title.replace("'", "''")[:80]
        safe_body = body.replace("'", "''")[:180]
        ps = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "Add-Type -AssemblyName System.Drawing; "
            "$n = New-Object System.Windows.Forms.NotifyIcon; "
            "$n.Icon = [System.Drawing.SystemIcons]::Warning; "
            "$n.Visible = $true; "
            f"$n.ShowBalloonTip(3000, '{safe_title}', '{safe_body}', 'Warning'); "
            "Start-Sleep -Milliseconds 500; $n.Dispose()"
        )
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", ps],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _maybe_contain(ip: str) -> str | None:
    if not _auto_block:
        return None
    if _never_block(ip):
        return "whitelist / lab NAT — bloqueio recusado"
    try:
        r = block_ip(ip, dry_run=not _execute)
        return r.message
    except Exception as e:
        return str(e)


def _fire(kind: str, ip: str, line: str) -> None:
    # Cooldown só no BURST (não silenciar FAIL/LOGIN/SUDO individuais)
    if kind == "BURST" and _in_cooldown(ip, kind):
        return
    if kind == "BURST":
        _arm_cooldown(ip, kind)
    contain_result = None
    if kind in ("BURST", "LOGIN"):
        contain_result = _maybe_contain(ip)
    rec = {
        "timestamp": _now_iso(),
        "kind": kind,
        "ip": ip,
        "line": (line or "")[-180:],
        "notified": True,
        "contain_result": contain_result,
        "next_step": _next_step(kind, ip),
    }
    with _lock:
        _alerts.append(rec)
    _notify(rec)


def classify_line(line: str) -> tuple[str, str] | None:
    """Devolve (kind, ip) para qualquer evento de auth relevante, ou None."""
    if not line or not line.strip():
        return None
    low = line.lower()
    if " cron[" in low or "crond[" in low:
        return None
    if not RE_EVENT.search(line):
        return None
    ip_m = RE_IP.search(line)
    ip = ip_m.group(1) if ip_m else "-"
    if "accepted password" in low or "accepted publickey" in low:
        return "LOGIN", ip
    if "invalid user" in low:
        return "INVALID", ip
    if (
        "failed password" in low
        or "failed publickey" in low
        or "authentication failure" in low
        or "maximum authentication" in low
        or "too many authentication" in low
    ):
        return "FAIL", ip
    if "sudo:" in low:
        return "SUDO", ip
    if "session opened" in low or "session closed" in low:
        return "SESSION", ip
    if "sshd[" in low or "disconnected from" in low or "connection closed" in low:
        return "SSH", ip
    return "AUTH", ip


def _handle_parsed(is_login: bool, ip: str, line: str, notify: bool) -> None:
    """Compat: Windows 4624/4625."""
    kind = "LOGIN" if is_login else "FAIL"
    _emit(kind, ip, line, notify)


def _emit(kind: str, ip: str, line: str, notify: bool) -> None:
    if ip and _is_whitelisted(ip):
        return
    now = time.time()
    if kind in ("FAIL", "INVALID") and ip and ip != "-":
        with _lock:
            _fail_times[ip].append(now)
            n = _prune_fails(ip, now)
        if notify:
            _fire(kind, ip, line)
            if n >= FAIL_THRESHOLD:
                _fire("BURST", ip, line)
        return
    if notify:
        _fire(kind, ip or "-", line)


def handle_line(line: str, notify: bool = True) -> None:
    parsed = classify_line(line)
    if not parsed:
        return
    kind, ip = parsed
    _emit(kind, ip, line, notify)


def _follow_file(path: Path) -> None:
    global _source, _hint
    _source = str(path)
    _hint = ""
    with path.open("r", errors="replace") as f:
        for line in f:
            if _stop.is_set():
                return
            handle_line(line, notify=False)
        while not _stop.is_set():
            line = f.readline()
            if line:
                handle_line(line, notify=True)
                continue
            try:
                if path.stat().st_size < f.tell():
                    f.seek(0)
            except OSError:
                pass
            _stop.wait(0.4)


def _journal_unit() -> str:
    for unit in ("ssh", "sshd"):
        try:
            r = subprocess.run(
                ["journalctl", "-u", unit, "-n", "1", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            blob = ((r.stdout or "") + (r.stderr or "")).lower()
            if r.returncode == 0 and "failed to" not in blob and "could not" not in blob:
                return unit
        except Exception:
            continue
    return "ssh"


def _follow_journal() -> None:
    global _source, _hint, _journal_proc
    unit = _journal_unit()
    _source = "journalctl auth/sshd/sudo"
    _hint = ""
    try:
        seed = subprocess.run(
            ["journalctl", "-n", "80", "--no-pager",
            "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "-t", "sshd", "-t", "sudo"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in (seed.stdout or "").splitlines():
            handle_line(line, notify=False)
    except Exception as e:
        _hint = str(e)

    try:
        _journal_proc = subprocess.Popen(
            ["journalctl", "-f", "-n", "0", "--no-pager",
             "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "-t", "sshd", "-t", "sudo"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        _hint = "journalctl não encontrado"
        _source = "nenhuma"
        while not _stop.is_set():
            _stop.wait(2.0)
        return
    assert _journal_proc.stdout
    try:
        while not _stop.is_set():
            line = _journal_proc.stdout.readline()
            if line == "" and _journal_proc.poll() is not None:
                break
            if line:
                handle_line(line, notify=True)
    finally:
        if _journal_proc and _journal_proc.poll() is None:
            try:
                _journal_proc.terminate()
            except Exception:
                pass
        _journal_proc = None


def _win_key(ev: dict) -> str:
    return "|".join(
        str(x)
        for x in (
            ev.get("time"),
            ev.get("event_id"),
            ev.get("src_ip"),
            ev.get("user"),
            ev.get("raw") or ev.get("message"),
        )
    )


def _follow_windows() -> None:
    global _source, _hint
    from windows_log_client import WindowsLogClient

    _source = "windows-security (4625/4624)"
    _hint = ""
    client = WindowsLogClient()
    seen: set[str] = set()
    first = True
    while not _stop.is_set():
        try:
            events = client.get_alerts(count=40)
        except Exception as e:
            _hint = str(e)
            events = []
        # get_alerts vem do mais recente; processar do mais antigo
        for ev in reversed(events):
            key = _win_key(ev)
            if key in seen:
                continue
            seen.add(key)
            ip = (ev.get("src_ip") or "").strip()
            if not ip or ip in ("-",):
                continue
            eid = int(ev.get("event_id") or 0)
            line = str(ev.get("raw") or ev.get("message") or "")
            is_login = eid == 4624
            is_fail = eid == 4625
            if not is_login and not is_fail:
                continue
            _handle_parsed(is_login, ip, line, notify=not first)
        if len(seen) > 3000:
            seen.clear()
            first = True
            continue
        first = False
        _stop.wait(POLL_SEC)


def _pick_and_run() -> None:
    global _source, _hint
    if os.name == "nt":
        _follow_windows()
        return
    path = find_auth()
    if path:
        try:
            _follow_file(path)
            return
        except PermissionError:
            _hint = "sem permissão em auth.log"
    # Linux sem ficheiro (ou sem permissão): journalctl, senão Windows
    if shutil.which("journalctl"):
        _follow_journal()
        return
    try:
        _follow_windows()
    except Exception:
        _source = "nenhuma"
        _hint = "sem auth.log / journalctl / Windows Event Log"
        while not _stop.wait(5.0):
            pass


def _run_loop() -> None:
    global _running, _hint
    _running = True
    try:
        _pick_and_run()
    except Exception as e:
        _hint = str(e)
    finally:
        _running = False


def start_background(auto_block: bool = False, execute: bool = False) -> dict:
    """Arranca o loop em thread. Idempotente — não cria dois tails."""
    global _auto_block, _execute, _thread
    with _lock:
        _auto_block = bool(auto_block)
        _execute = bool(execute)
        already = _thread is not None and _thread.is_alive()
        if not already:
            _stop.clear()
            _thread = threading.Thread(target=_run_loop, name="soc-alerter", daemon=True)
            _thread.start()
    return status()


def stop_background() -> None:
    global _thread, _journal_proc, _running
    _stop.set()
    if _journal_proc and _journal_proc.poll() is None:
        try:
            _journal_proc.terminate()
        except Exception:
            pass
    t = _thread
    if t is not None and t.is_alive() and t is not threading.current_thread():
        t.join(timeout=3.0)
    _thread = None
    _running = False


def get_alerts() -> list[dict]:
    with _lock:
        return list(_alerts)


def status() -> dict:
    with _lock:
        n = len(_alerts)
        alive = _thread is not None and _thread.is_alive()
    return {
        "running": bool(_running or alive),
        "source": _source,
        "hint": _hint,
        "auto_block": _auto_block,
        "execute": _execute,
        "fail_threshold": FAIL_THRESHOLD,
        "window_sec": WINDOW_SEC,
        "cooldown_sec": COOLDOWN_SEC,
        "alert_count": n,
    }
