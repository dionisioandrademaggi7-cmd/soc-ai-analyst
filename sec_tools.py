from __future__ import annotations

import shutil
import subprocess


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        text = ((p.stdout or "") + (p.stderr or "")).strip()
        return p.returncode, text
    except FileNotFoundError:
        return 127, "comando nao encontrado"
    except Exception as e:
        return 1, str(e)


def ufw_status() -> dict:
    if not shutil.which("ufw"):
        return {"ok": False, "tool": "ufw", "message": "ufw nao instalado"}
    code, text = _run(["sudo", "-n", "ufw", "status", "verbose"])
    if code != 0:
        code, text = _run(["ufw", "status", "verbose"])
    return {"ok": code == 0, "tool": "ufw", "message": text or "sem saida"}


def fail2ban_status() -> dict:
    if not shutil.which("fail2ban-client"):
        return {"ok": False, "tool": "fail2ban", "message": "fail2ban-client nao instalado"}
    code, text = _run(["sudo", "-n", "fail2ban-client", "status", "sshd"])
    if code != 0:
        code, text = _run(["fail2ban-client", "status"])
    return {"ok": code == 0, "tool": "fail2ban", "message": text or "sem saida"}


def host_defense_snapshot() -> dict:
    return {"ufw": ufw_status(), "fail2ban": fail2ban_status()}