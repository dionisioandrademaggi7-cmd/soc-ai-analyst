"""
Cliente mínimo para a API REST do Splunk.
Usa busca em modo 'oneshot' (retorna os resultados direto na resposta,
sem precisar fazer polling de um search job assíncrono).

Docs: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
"""
import requests
from typing import Optional
from config import SplunkConfig


class SplunkClient:
    def __init__(self, cfg: SplunkConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = cfg.verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {cfg.token}",
        })

    def search(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_count: int = 100,
    ) -> list[dict]:
        """Executa uma busca SPL e retorna a lista de eventos (dicts)."""
        # A API exige que a query comece com 'search' (ou outro comando geradador)
        query = spl_query.strip()
        if not query.lower().startswith(("search", "|")):
            query = f"search {query}"

        url = f"{self.cfg.base_url}/services/search/jobs"
        resp = self.session.post(
            url,
            data={
                "search": query,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "count": max_count,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
            },
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])

    def get_alerts(self, count: int = 50) -> list[dict]:
        """Busca os alertas/eventos notáveis definidos em SPLUNK_ALERT_QUERY."""
        return self.search(self.cfg.alert_query, max_count=count)

    def get_context_for_event(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        earliest_time: str = "-1h",
        latest_time: str = "+1h",
        max_count: int = 50,
    ) -> list[dict]:
        """
        Busca eventos relacionados (mesmo host e/ou usuário) numa janela de tempo,
        para dar contexto a uma investigação de incidente.
        """
        filters = []
        if host:
            filters.append(f'host="{host}"')
        if user:
            filters.append(f'user="{user}"')
        if not filters:
            return []
        spl = f"search index=* {' '.join(filters)} | sort - _time"
        return self.search(spl, earliest_time=earliest_time, latest_time=latest_time, max_count=max_count)