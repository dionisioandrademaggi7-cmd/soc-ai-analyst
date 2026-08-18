"""
Camada de análise com IA (Claude).
Duas funções principais:
  - triage_alert: classifica um alerta bruto (severidade, categoria, próximos passos)
  - investigate_incident: dado um alerta + eventos de contexto, produz uma análise
    de incidente mais profunda (timeline, hipótese de causa raiz, recomendações)
"""
import json
import re
from dataclasses import dataclass, field, fields

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from config import GeminiConfig

TRIAGE_SYSTEM_PROMPT = """\
Você é um analista de SOC sênior revisando o trabalho de um analista júnior.
Sua tarefa é triar UM alerta de segurança bruto (em JSON) e devolver APENAS um \
objeto JSON válido, sem texto antes ou depois, sem markdown, com este formato exato:

{
  "severity": "critical" | "high" | "medium" | "low" | "informational",
  "category": string,                // ex: "malware", "phishing", "brute_force",
                                      // "insider_threat", "misconfiguration",
                                      // "recon", "data_exfiltration", "false_positive", "other"
  "false_positive_likelihood": number,   // 0 a 100
  "confidence": "high" | "medium" | "low",
  "summary": string,                 // 2-3 frases, direto ao ponto
  "indicators": [string],            // IOCs / evidências relevantes extraídas do evento
  "mitre_attack": [string],          // técnicas ATT&CK aplicáveis, ex: "T1110 - Brute Force" (vazio se não houver)
  "recommended_actions": [string],   // ações concretas e priorizadas para o analista júnior
  "escalate": boolean                // true se deve ser escalado para um analista sênior
}

Seja direto e específico. Baseie-se apenas nos dados do evento fornecido; não invente campos que não existem no log.\
"""

INVESTIGATE_SYSTEM_PROMPT = """\
Você é um analista de SOC sênior conduzindo a investigação aprofundada de um incidente.
Você recebe o alerta original e uma lista de eventos de contexto (mesmo host/usuário, \
janela de tempo próxima). Produza um relatório em markdown, direto e estruturado, com \
exatamente estas seções:

## Resumo Executivo
## Linha do Tempo
## Hipótese de Causa Raiz
## Escopo / Blast Radius
## Indicadores de Comprometimento
## Recomendações de Contenção e Remediação
## Próximos Passos para o Analista Júnior

Seja concreto: cite hosts, usuários, horários e comandos/eventos específicos observados \
nos dados fornecidos. Não invente informações que não estejam nos dados. Se os dados de \
contexto forem insuficientes para alguma seção, diga isso explicitamente e liste que \
buscas adicionais o analista deveria fazer.\
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
    escalate: bool = False


class AIAnalyst:
    def __init__(self, cfg: GeminiConfig):
        self.client = genai.Client(api_key=cfg.api_key)
        self.model = cfg.model

    def _extract_json(self, text: str) -> dict:
        # Remove eventuais cercas de código, caso o modelo as inclua
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
        }

    def triage_alert(self, alert: dict) -> TriageResult:
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=json.dumps(alert, ensure_ascii=False, default=str),
                config=types.GenerateContentConfig(
                    system_instruction=TRIAGE_SYSTEM_PROMPT,
                    max_output_tokens=1024,
                    response_mime_type="application/json",
                ),
            )
        except genai_errors.APIError as e:
            # falha de rede/API (timeout, 429, chave inválida, etc.) não deve derrubar o pipeline
            parsed = self._fallback_result(f"Falha ao chamar a API do Gemini: {e}")
            return TriageResult(raw_alert=alert, **parsed)

        text = response.text
        try:
            parsed = self._extract_json(text)
        except (json.JSONDecodeError, TypeError):
            # fallback defensivo: não deixa o pipeline quebrar por causa de 1 alerta malformado
            parsed = self._fallback_result(
                f"Falha ao interpretar resposta da IA. Resposta bruta: {text[:300]}"
            )

        # filtra apenas chaves que existem no dataclass, e garante que as obrigatórias existam
        # (o modelo pode devolver campos a mais/a menos mesmo com instrução estrita)
        valid_fields = {f.name for f in fields(TriageResult)} - {"raw_alert"}
        filtered = {k: v for k, v in parsed.items() if k in valid_fields}
        missing = valid_fields - filtered.keys() - {"indicators", "mitre_attack", "recommended_actions", "escalate"}
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
            response = self.client.models.generate_content(
                model=self.model,
                contents=json.dumps(payload, ensure_ascii=False, default=str),
                config=types.GenerateContentConfig(
                    system_instruction=INVESTIGATE_SYSTEM_PROMPT,
                    max_output_tokens=2048,
                ),
            )
        except genai_errors.APIError as e:
            return (
                "## Resumo Executivo\n\n"
                f"⚠️ Não foi possível gerar a investigação: falha ao chamar a API do Gemini ({e}).\n\n"
                "Revise o alerta e os eventos de contexto manualmente."
            )
        return response.text