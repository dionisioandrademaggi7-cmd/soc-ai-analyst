"""
SOC AI Analyst — CLI

Uso:
  python main.py triage --count 20
  python main.py investigate --host 10.0.0.5 --user jdoe
  python main.py investigate --host 10.0.0.5 --alert-index 0   # reusa alerta já triado

Fase 1: valida a lógica no terminal. A ideia é que splunk_client, ai_analyst e
report_generator sejam reaproveitados depois como backend de uma API web (ex: FastAPI),
sem precisar reescrever a lógica de negócio.
"""
import argparse
import sys

from local_log_client import LocalLogClient
from config import settings
from splunk_client import SplunkClient
from mock_splunk_client import MockSplunkClient
from ai_analyst import AIAnalyst
import report_generator as rg


def cmd_triage(args):
    if args.mock:
        splunk = MockSplunkClient()

    elif getattr(args, "local", False):
        splunk = LocalLogClient()
    else:
        splunk = SplunkClient(settings.splunk)

    analyst = AIAnalyst(settings.groq)

    if args.mock:
        fonte = "DADOS SIMULADOS (mock)"
    elif getattr(args, "local", False):
        fonte = "LOGS LOCAIS (auth.log)"
    else:
        fonte = "Splunk real"

    print(f"[*] Fonte de dados: {fonte}")


    alerts = splunk.get_alerts(count=args.count)
    print(f"[*] {len(alerts)} alertas encontrados. Iniciando triagem...")

    results = []
    for i, alert in enumerate(alerts, 1):
        print(f"    [{i}/{len(alerts)}] triando...", end="\r")
        results.append(analyst.triage_alert(alert))
    print()

    report = rg.build_triage_report(results)
    path = rg.save_report(report, settings.reports_dir, prefix="triage")

    escalated = [r for r in results if r.escalate]
    print(f"[✓] Relatório salvo em: {path}")
    print(f"[!] {len(escalated)} alerta(s) marcado(s) para escalonar.")

def cmd_investigate(args):
    if args.mock:
        splunk = MockSplunkClient()
    elif getattr(args, "local", False):
        splunk = LocalLogClient()
    else:
         splunk = SplunkClient(settings.splunk)

    analyst = AIAnalyst(settings.groq)

    if not args.host and not args.user:
        print("Erro: informe --host e/ou --user para buscar contexto.", file=sys.stderr)
        sys.exit(1)

    alert = {
        "host": args.host,
        "user": args.user,
        "note": "Investigação disparada manualmente via CLI (sem alerta de origem específico).",
    }

    print(f"[*] Buscando eventos de contexto (host={args.host}, user={args.user})...")
    context = splunk.get_context_for_event(
        host=args.host, user=args.user,
        earliest_time=args.earliest, latest_time=args.latest,
    )
    print(f"[*] {len(context)} eventos de contexto encontrados. Investigando...")

    investigation_md = analyst.investigate_incident(alert, context)
    report = rg.build_investigation_report(alert, investigation_md)
    path = rg.save_report(report, settings.reports_dir, prefix="investigation")

    print(f"[✓] Relatório salvo em: {path}")

def cmd_contain(args):
    from containment import block_ip, unblock_ip, status

    dry = not args.execute  # padrao seguro: dry-run
    if args.status:
        print(status())
        return
    if args.block:
        r = block_ip(args.block, dry_run=dry)
        tag = "DRY-RUN" if r.dry_run else "LIVE"
        print(f"[{tag}] block {r.target}: {r.message} ({'ok' if r.success else 'falhou'})")
        return
    if args.unblock:
        r = unblock_ip(args.unblock, dry_run=dry)
        tag = "DRY-RUN" if r.dry_run else "LIVE"
        print(f"[{tag}] unblock {r.target}: {r.message} ({'ok' if r.success else 'falhou'})")
        return
    print("Use --block IP, --unblock IP ou --status")


def main():
    parser = argparse.ArgumentParser(description="SOC AI Analyst — triagem e investigação assistidas por IA")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_triage = subparsers.add_parser("triage", help="Busca e tria alertas pendentes no Splunk")
    p_triage.add_argument("--count", type=int, default=20, help="Número máximo de alertas a buscar")
    p_triage.add_argument("--mock", action="store_true", help="Usa dados simulados em vez de um Splunk real")
    p_triage.add_argument("--local", action="store_true", help="Lê logs locais (auth.log) em vez de Splunk")
    p_triage.set_defaults(func=cmd_triage)

    p_inv = subparsers.add_parser("investigate", help="Investiga um incidente a partir de host/usuário")
    p_inv.add_argument("--host", type=str, default=None)
    p_inv.add_argument("--user", type=str, default=None)
    p_inv.add_argument("--earliest", type=str, default="-1h")
    p_inv.add_argument("--latest", type=str, default="+1h")
    p_inv.add_argument("--mock", action="store_true", help="Usa dados simulados em vez de um Splunk real")
    p_inv.add_argument("--local", action="store_true", help="Lê logs locais (auth.log) em vez de Splunk")
    p_inv.set_defaults(func=cmd_investigate)

    p_contain = subparsers.add_parser("contain", help="Contencao local (bloquear/desbloquear IP via ufw)")
    p_contain.add_argument("--block", type=str, default=None, help="IP para bloquear")
    p_contain.add_argument("--unblock", type=str, default=None, help="IP para desbloquear")
    p_contain.add_argument("--status", action="store_true", help="Mostra regras ufw")
    p_contain.add_argument("--dry-run", action="store_true", default=True, help="Nao executa, so mostra (padrao)")
    p_contain.add_argument("--execute", action="store_true", help="Executa de verdade (desliga dry-run)")
    p_contain.set_defaults(func=cmd_contain)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

