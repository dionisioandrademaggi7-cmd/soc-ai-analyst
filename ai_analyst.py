"""
Camada de análise com IA (Groq).
Duas funções principais:
  - triage_alert: classifica um alerta bruto
  - investigate_incident: análise aprofundada de incidente
"""
import json
import re
from dataclasses import dataclass, field, fields

from groq import Groq
from config import GroqConfig

TRIAGE_SYSTEM_PROMPT = """\
Você é um analista de SOC sênior com experiência em resposta a incidentes.
Sua tarefa é triar UM alerta de segurança bruto (em JSON) e devolver APENAS um \
objeto JSON válido, sem texto antes ou depois, sem markdown, com este formato exato:

{
  "severity": "critical" | "high" | "medium" | "low" | "informational",
  "category": string,
  "false_positive_likelihood": number,
  "confidence": "high" | "medium" | "low",
  "summary": string,
  "indicators": [string],
  "mitre_attack": [string],
  "attack_stage": string,
  "recommended_actions": [string],
  "containment_actions": [string],
  "escalate": boolean,
  "priority_score": number
}

Regras de análise:
- Seja rigoroso. Prefira severidade mais alta quando houver dúvida em ataques de autenticação, lateral movement ou exfiltração.
- "attack_stage" deve indicar a fase provável (ex: "Initial Access", "Execution", "Persistence", "Credential Access", "Lateral Movement", "Exfiltration", "Impact").
- "containment_actions" deve listar ações DEFENSIVAS concretas e imediatas (ex: "Bloquear IP de origem no firewall", "Desabilitar conta do usuário", "Isolar host da rede", "Forçar reset de senha", "Revogar sessões ativas").
- "recommended_actions" são os próximos passos de investigação.
- "priority_score" de 1 a 100 (100 = urgência máxima).
- Baseie-se apenas nos dados fornecidos. Não invente evidências.
- Responda sempre em português do Brasil nos campos de texto (summary, actions, etc.).
"""

INVESTIGATE_SYSTEM_PROMPT = """\
Você é um analista de SOC sênior conduzindo investigação aprofundada de incidente.
Você recebe o alerta original e eventos de contexto. Produza um relatório em markdown \
em português do Brasil, com exatamente estas seções:

## Resumo Executivo
## Classificação e Severidade
## Linha do Tempo
## Hipótese de Causa Raiz
## Escopo / Blast Radius
## Indicadores de Comprometimento (IOCs)
## Técnicas MITRE ATT&CK
## Ações de Contenção Imediatas
## Ações de Erradicação e Recuperação
## Monitoramento Adicional Recomendado
## Próximos Passos para o Analista

Regras:
- Seja concreto: cite hosts, usuários, IPs, horários e eventos reais dos dados.
- Em "Ações de Contenção Imediatas" liste só medidas defensivas (bloquear, isolar, desabilitar, revogar, resetar).
- Não invente dados que não estejam no contexto.
- Se faltar informação, diga explicitamente o que precisa ser coletado.
"""

@dataclass
class TriageResult:
    raw_alert: dict
    severity: str
    category: str
    false_positive_likelihood: float
    confidence: str
    summary: str
    indicators: list = field(default_factory=list)
    mitre_attack: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)
    containment_actions: list = field(default_factory=list)
    attack_stage: str = "Unknown"
    priority_score: float = 50.0
    escalate: bool = False

class AIAnalyst:
    def __init__(self, cfg: GroqConfig):
        self.client = Groq(api_key=cfg.api_key)
        self.model = cfg.model

    def _extract_json(self, text: str) -> dict:
        cleaned = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
        return json.loads(cleaned)

    def _fallback_result(self, reason: str) -> dict:
        return {
            "severity": "medium",
            "category": "other",
            "false_positive_likelihood": 50,
            "confidence": "low",
            "summary": reason,
            "indicators": [],
            "mitre_attack": [],
            "recommended_actions": ["Revisar manualmente — não foi possível obter uma triagem confiável da IA."],
            "escalate": True,
            "containment_actions": [],
            "attack_stage": "Unknown",
            "priority_score": 50,
        }

    def triage_alert(self, alert: dict) -> TriageResult:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(alert, ensure_ascii=False, default=str)},
                ],
                temperature=0.2,
                max_tokens=1536,
            )
            text = response.choices[0].message.content
        except Exception as e:
            parsed = self._fallback_result(f"Falha ao chamar a API do Groq: {e}")
            return TriageResult(raw_alert=alert, **parsed)

        try:
            parsed = self._extract_json(text)
        except (json.JSONDecodeError, TypeError):
            parsed = self._fallback_result(
                f"Falha ao interpretar resposta da IA. Resposta bruta: {str(text)[:300]}"
            )

        valid_fields = {f.name for f in fields(TriageResult)} - {"raw_alert"}
        filtered = {k: v for k, v in parsed.items() if k in valid_fields}
        missing = valid_fields - filtered.keys() - {
            "indicators",
            "mitre_attack",
            "recommended_actions",
            "containment_actions",
            "attack_stage",
            "priority_score",
            "escalate",
        }
        required = {"severity", "category", "false_positive_likelihood", "confidence", "summary"}
        if missing & required:
            filtered = self._fallback_result(
                f"Resposta da IA incompleta, faltando campos: {sorted(missing & required)}"
            )

        return TriageResult(raw_alert=alert, **filtered)

    def investigate_incident(self, alert: dict, context_events: list[dict]) -> str:
        payload = {
            "alerta_original": alert,
            "eventos_de_contexto": context_events,
        }
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": INVESTIGATE_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
                ],
                temperature=0.3,
                max_tokens=2048,
            )
            return response.choices[0].message.content
        except Exception as e:
            return (
                "## Resumo Executivo\n\n"
                f"⚠️ Não foi possível gerar a investigação: falha ao chamar a API do Groq ({e}).\n\n"
                "Revise o alerta e os eventos de contexto manualmente."
            )