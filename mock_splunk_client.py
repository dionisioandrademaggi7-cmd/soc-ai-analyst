"""
Cliente "mock" com a MESMA interface do SplunkClient (get_alerts, get_context_for_event),
mas gerando dados simulados e realistas em vez de chamar uma API de verdade.

Objetivo: validar toda a lógica de triagem/investigação/relatório enquanto o acesso
a um Splunk real não está disponível. Quando o Splunk chegar, troca-se
MockSplunkClient por SplunkClient em main.py — nenhuma outra linha muda.
"""
import random
from datetime import datetime, timedelta, timezone


def _now_minus(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


# Pool de alertas simulados cobrindo os tipos mais comuns que um júnior de SOC vê no dia a dia
_ALERT_POOL = [
    {
        "_time": _now_minus(4),
        "rule_name": "Multiple Failed Logins Followed By Success",
        "host": "srv-web-01",
        "user": "jsilva",
        "src_ip": "203.0.113.5",
        "dest_ip": "10.0.2.15",
        "event_count": 247,
        "sourcetype": "auth",
        "raw": "247 failed SSH attempts from 203.0.113.5 in 3min, followed by successful login as jsilva",
    },
    {
        "_time": _now_minus(12),
        "rule_name": "Outbound Connection to Known Malicious IP",
        "host": "ws-finance-14",
        "user": "mrodrigues",
        "src_ip": "10.0.5.22",
        "dest_ip": "185.220.101.7",
        "sourcetype": "firewall",
        "raw": "Outbound TCP 443 to 185.220.101.7 (flagged on threat intel feed), process: powershell.exe",
    },
    {
        "_time": _now_minus(30),
        "rule_name": "Internal Port Scan Detected",
        "host": "ws-dev-03",
        "user": "svc_monitoring",
        "src_ip": "10.0.1.99",
        "dest_ip": "10.0.0.0/24",
        "sourcetype": "ids",
        "raw": "Sequential SYN scan across 254 hosts on subnet 10.0.0.0/24 from known monitoring service account",
    },
    {
        "_time": _now_minus(55),
        "rule_name": "Suspicious Email Attachment Executed",
        "host": "ws-hr-08",
        "user": "aoliveira",
        "src_ip": "10.0.3.44",
        "dest_ip": None,
        "sourcetype": "endpoint",
        "raw": "invoice_2026_urgent.docm executed macro spawning cmd.exe -> certutil.exe -urlcache -split",
    },
    {
        "_time": _now_minus(80),
        "rule_name": "Large Data Transfer to External Storage",
        "host": "srv-fileserver-02",
        "user": "cnunes",
        "src_ip": "10.0.4.10",
        "dest_ip": "198.51.100.23",
        "bytes_out": 4_800_000_000,
        "sourcetype": "netflow",
        "raw": "4.8GB uploaded to external IP over HTTPS outside business hours (02:15 local time)",
    },
    {
        "_time": _now_minus(3),
        "rule_name": "Vulnerability Scanner Traffic",
        "host": "ws-sec-01",
        "user": "svc_qualys",
        "src_ip": "10.0.1.50",
        "dest_ip": "10.0.0.0/16",
        "sourcetype": "ids",
        "raw": "Traffic pattern matches known signature of authorized vulnerability scanner (Qualys agent)",
    },
]

_CONTEXT_TEMPLATES = [
    "Process creation: {proc} launched by {user} on {host}",
    "Network connection: {host} -> {dest} on port {port}",
    "File written: C:\\Users\\{user}\\AppData\\Local\\Temp\\{fname}",
    "Registry modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run by {user}",
    "Login event: {user} authenticated on {host} via {method}",
]


class MockSplunkClient:
    def __init__(self, *_, **__):
        # aceita os mesmos argumentos do SplunkClient real (cfg) mas ignora — não precisa de credenciais
        pass

    def get_alerts(self, count: int = 50) -> list[dict]:
        pool = _ALERT_POOL * ((count // len(_ALERT_POOL)) + 1)
        return pool[:count]

    def get_context_for_event(
        self,
        host: str = None,
        user: str = None,
        earliest_time: str = "-1h",
        latest_time: str = "+1h",
        max_count: int = 50,
    ) -> list[dict]:
        events = []
        for i in range(min(max_count, 8)):
            template = random.choice(_CONTEXT_TEMPLATES)
            events.append({
                "_time": _now_minus(random.randint(1, 90)),
                "host": host or "unknown-host",
                "user": user or "unknown-user",
                "raw": template.format(
                    proc=random.choice(["cmd.exe", "powershell.exe", "rundll32.exe", "svchost.exe"]),
                    user=user or "unknown-user",
                    host=host or "unknown-host",
                    dest=random.choice(["10.0.0.5", "185.220.101.7", "8.8.8.8"]),
                    port=random.choice([443, 445, 3389, 22]),
                    fname=random.choice(["update.tmp", "cache.dat", "svc.dll"]),
                    method=random.choice(["RDP", "SSH", "local"]),
                ),
            })
        return sorted(events, key=lambda e: e["_time"], reverse=True)