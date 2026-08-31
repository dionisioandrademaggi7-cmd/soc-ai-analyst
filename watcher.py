"""
Alerta Failed / Accepted no auth.log.
No arranque le as ultimas linhas + segue as novas.
  python watcher.py
  python watcher.py --block --execute
"""
from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

from session_watch import DEFAULT_WHITELIST
from containment import block_ip

AUTH_CANDIDATES = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
]
RE_LINE = re.compile(
    r"(Failed password|Invalid user|authentication failure|Accepted password|Accepted publickey).*?"
    r"(\d{1,3}(?:\.\d{1,3}){3})",
    re.I,
)


def find_auth() -> Path | None:
    for p in AUTH_CANDIDATES:
        if p.exists():
            return p
    return None


def handle(line: str, do_block: bool, execute: bool):
    m = RE_LINE.search(line)
    if not m:
        return
    kind, ip = m.group(1), m.group(2)
    if ip in DEFAULT_WHITELIST:
        return
    tag = "LOGIN" if "Accepted" in kind else "TENTATIVA"
    print(f"[{tag}] {kind} ip={ip}")
    print(f"    {line.strip()}")
    if do_block:
        r = block_ip(ip, dry_run=not execute)
        print(f"    contain={'LIVE' if execute else 'DRY'} {r.message}")


def tail_and_follow(path: Path, do_block: bool, execute: bool):
    print(f"[*] ficheiro: {path}")
    with path.open("r", errors="replace") as f:
        lines = f.readlines()
        print(f"[*] varredura inicial ({len(lines)} linhas, mostro as que casam)")
        for line in lines[-80:]:
            handle(line, False, False)
        print("[*] a vigiar linhas novas...")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.4)
                continue
            handle(line, do_block, execute)


def follow_journal(do_block: bool, execute: bool):
    import subprocess
    print("[*] auth.log ausente — journalctl -u ssh -f")
    proc = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "40", "--no-pager"],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout
    for line in proc.stdout:
        handle(line, do_block, execute)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--block", action="store_true")
    p.add_argument("--execute", action="store_true")
    args = p.parse_args()

    path = find_auth()
    if path:
        try:
            tail_and_follow(path, args.block, args.execute)
        except PermissionError:
            print("[x] sem permissao em auth.log. Corre: sudo python watcher.py")
            return
    else:
        follow_journal(args.block, args.execute)


if __name__ == "__main__":
    main()