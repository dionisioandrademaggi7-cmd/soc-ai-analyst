"""
Configuração central do SOC AI Analyst.
Carrega variáveis de ambiente (.env) e expõe como objeto único.
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(
            f"Variável de ambiente obrigatória ausente: {name}. "
            f"Copie .env.example para .env e preencha os valores."
        )
    return value


@dataclass
class SplunkConfig:
    host: str
    port: int
    token: str
    verify_ssl: bool
    alert_query: str

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


@dataclass
class GeminiConfig:
    api_key: str
    model: str


class Settings:
    def __init__(self):
        self.splunk = SplunkConfig(
            host=_get("SPLUNK_HOST", default="localhost"),
            port=int(_get("SPLUNK_PORT", "8089")),
            token=_get("SPLUNK_TOKEN", default=""),
            verify_ssl=_get("SPLUNK_VERIFY_SSL", "true").lower() == "true",
            alert_query=_get("SPLUNK_ALERT_QUERY", "search index=notable status=unassigned"),
        )
        self.gemini = GeminiConfig(
            api_key=_get("GEMINI_API_KEY", required=True),
            model=_get("GEMINI_MODEL", "gemini-3-flash-preview"),
        )
        self.reports_dir = _get("REPORTS_DIR", "reports")


settings = Settings()