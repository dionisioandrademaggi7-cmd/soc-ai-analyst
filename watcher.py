"""
Alerta autónomo Failed / Accepted no auth.log (ou Event Log no Windows).

Já não é preciso chamar uma função CLI de triagem a cada evento:
o loop dispara sozinho (som + banner) quando há uma rajada de falhas
SSH/logon ou um login bem-sucedido fora da whitelist.

Para o relatório detalhado, use o SOC AI Analyst (dashboard: Triagem /
Investigar). Bloqueio ufw live só com --block --execute.

  python watcher.py
  python watcher.py --block
  python watcher.py --block --execute
"""
from __future__ import annotations

import argparse
import time

from alerter import start_background, stop_background, status


def main():
    p = argparse.ArgumentParser(
        description="Watcher autónomo de SSH/logon (alerta sozinho)."
    )
    p.add_argument(
        "--block",
        action="store_true",
        help="Após BURST/LOGIN suspeito, chamar containment.block_ip (dry-run por omissão).",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Com --block: executar ufw deny de verdade (human-in-the-loop).",
    )
    args = p.parse_args()

    st = start_background(auto_block=args.block, execute=args.execute)
    print(
        f"[*] alerter autónomo a correr · fonte={st.get('source')} "
        f"limiar={st.get('fail_threshold')} falhas / {st.get('window_sec')}s"
    )
    print(
        "[*] os alertas soam sozinhos. Relatório detalhado: abra o SOC AI Analyst "
        "(Triagem / Investigar)."
    )
    if args.block:
        modo = "LIVE" if args.execute else "DRY-RUN"
        print(f"[*] contain={modo} (whitelist + 10.0.2.2 / 10.0.2.15 nunca bloqueados)")
        if not args.execute:
            print("[*] ufw live exige --execute (ou o botão «Executar block» no dashboard).")
    if st.get("hint"):
        print(f"[!] {st['hint']}")

    try:
        while True:
            time.sleep(1)
            cur = status()
            if not cur.get("running"):
                hint = cur.get("hint") or "loop terminou"
                print(f"[x] alerter parou: {hint}")
                break
    except KeyboardInterrupt:
        print("\n[*] a parar...")
    finally:
        stop_background()


if __name__ == "__main__":
    main()
