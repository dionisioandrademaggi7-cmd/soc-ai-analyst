"""
Monta relatórios em markdown a partir dos resultados de triagem/investigação
e salva em disco com timestamp.
"""
import os
from datetime import datetime, timezone

from ai_analyst import TriageResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")


def build_triage_report(results: list[TriageResult]) -> str:
    results_sorted = sorted(results, key=lambda r: SEVERITY_ORDER.get(r.severity, 9))

    lines = [
        "# Relatório de Triagem de Alertas",
        f"_Gerado em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
        f"**Total de alertas analisados:** {len(results)}",
        "",
        "## Resumo",
        "",
        "| Severidade | Categoria | Falso Positivo (%) | Escalar? | Resumo |",
        "|---|---|---|---|---|",
    ]
    for r in results_sorted:
        emoji = SEVERITY_EMOJI.get(r.severity, "")
        lines.append(
            f"| {emoji} {r.severity} | {r.category} | {r.false_positive_likelihood} | "
            f"{'⚠️ Sim' if r.escalate else 'Não'} | {r.summary} |"
        )

    lines.append("")
    lines.append("## Detalhamento por Alerta")
    for i, r in enumerate(results_sorted, 1):
        lines += [
            "",
            f"### {i}. {SEVERITY_EMOJI.get(r.severity, '')} [{r.severity.upper()}] {r.category}",
            f"- **Confiança da análise:** {r.confidence}",
            f"- **Probabilidade de falso positivo:** {r.false_positive_likelihood}%",
            f"- **Escalar para sênior:** {'Sim' if r.escalate else 'Não'}",
            f"- **Resumo:** {r.summary}",
        ]
        if r.indicators:
            lines.append(f"- **Indicadores:** {', '.join(r.indicators)}")
        if r.mitre_attack:
            lines.append(f"- **MITRE ATT&CK:** {', '.join(r.mitre_attack)}")
        if r.recommended_actions:
            lines.append("- **Ações recomendadas:**")
            for action in r.recommended_actions:
                lines.append(f"  - {action}")

    return "\n".join(lines)


def build_investigation_report(alert: dict, investigation_markdown: str) -> str:
    header = [
        "# Relatório de Investigação de Incidente",
        f"_Gerado em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
        "## Alerta Original (dados brutos)",
        "```json",
        str(alert),
        "```",
        "",
    ]
    return "\n".join(header) + investigation_markdown


def save_report(content: str, reports_dir: str, prefix: str) -> str:
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, f"{prefix}_{_timestamp()}.md")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath