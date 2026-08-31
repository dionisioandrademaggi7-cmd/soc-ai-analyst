"""
Vigia auth.log. Failed / Accepted de IP fora da whitelist -> alerta.
Opcional: contain live.
Uso:
  python watcher.py
  python watcher.py --block --execute
"""
from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

from session_watch import DEFAULT_WHITELIST, find_foreign_sessions
from containment import block_ip

AUTH = Path("/var/log/auth.log")
RE_LINE = re.compile(
    r"(Failed password|Invalid user|Accepted password|Accepted publickey).*?"
    r"(\d{1,3}(?:\.\d{1,3}){3})"
)


def follow(path: Path):
    path.touch(exist_ok=True)
    with path.open("r", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def handle(line: str, do_block: bool, execute: bool):
    m = RE_LINE.search(line)
    if not m:
        return
    kind, ip = m.group(1), m.group(2)
    if ip in DEFAULT_WHITELIST:
        return
    print(f"[ALERTA] {kind} ip={ip}")
    if "Accepted" in kind:
        print(f"[LOGIN] sessao de {ip} — IP fora da whitelist")
    if do_block:
        r = block_ip(ip, dry_run=not execute)
        tag = "DRY" if r.dry_run else "LIVE"
        print(f"[{tag}] contain {ip}: {r.message}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--block", action="store_true")
    p.add_argument("--execute", action="store_true")
    args = p.parse_args()

    print("[*] watcher auth.log")
    if not AUTH.exists():
        print("sem /var/log/auth.log — este watcher e para Ubuntu")
        return

    foreign = find_foreign_sessions()
    for s in foreign:
        print(f"[!] sessao ja aberta: {s.user} {s.ip}")

    for line in follow(AUTH):
        handle(line, args.block, args.execute)


if __name__ == "__main__":
    main()