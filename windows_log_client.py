"""
Le eventos de seguranca do Windows (Event Log) e expoe no mesmo formato
dos outros clients (lista de dicts para triage).
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone


class WindowsLogClient:
    """Security log: 4625 (failed logon), 4624 (success)."""

    def get_alerts(self, count: int = 20) -> list[dict]:
        events = self._query_events(max_events=max(count * 3, 30))
        alerts = []
        for ev in events:
            parsed = self._event_to_alert(ev)
            if parsed:
                alerts.append(parsed)
            if len(alerts) >= count:
                break
        return alerts

    def get_context_for_event(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest_time: str = "-1h",
        latest_time: str = "+1h",
    ) -> list[dict]:
        events = self._query_events(max_events=50)
        out = []
        for ev in events:
            alert = self._event_to_alert(ev)
            if not alert:
                continue
            if user and user.lower() not in str(alert.get("user", "")).lower():
                continue
            if host and host.lower() not in str(alert.get("host", "")).lower():
                continue
            out.append(alert)
        return out

    def _query_events(self, max_events: int = 30) -> list[dict]:
        # PowerShell: ultimos eventos 4625 e 4624
        ps = f"""
        Get-WinEvent -FilterHashtable @{{
            LogName = 'Security'
            Id = 4625, 4624
        }} -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        ForEach-Object {{
            $xml = [xml]$_.ToXml()
            $data = @{{}}
            foreach ($n in $xml.Event.EventData.Data) {{
                $data[$n.Name] = $n.'#text'
            }}
            [PSCustomObject]@{{
                TimeCreated = $_.TimeCreated.ToString('o')
                Id = $_.Id
                TargetUserName = $data['TargetUserName']
                IpAddress = $data['IpAddress']
                WorkstationName = $data['WorkstationName']
                LogonType = $data['LogonType']
                Status = $data['Status']
                FailureReason = $data['FailureReason']
                SubjectUserName = $data['SubjectUserName']
            }}
        }} | ConvertTo-Json -Compress
        """
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=60,
            )
            raw = (proc.stdout or "").strip()
            if not raw:
                return []
            import json
            data = json.loads(raw)
            if isinstance(data, dict):
                return [data]
            return data
        except Exception:
            return []

    def _event_to_alert(self, ev: dict) -> dict | None:
        eid = int(ev.get("Id") or 0)
        user = (ev.get("TargetUserName") or "").strip()
        if not user or user.endswith("$"):
            # ignora contas de maquina
            if eid != 4625:
                return None

        ip = (ev.get("IpAddress") or "").strip()
        if ip in ("-", "::1", "127.0.0.1"):
            ip = ip if ip not in ("-",) else None

        host = (ev.get("WorkstationName") or "").strip() or "windows-local"
        ts = ev.get("TimeCreated") or datetime.now(timezone.utc).isoformat()

        if eid == 4625:
            summary = f"Falha de logon Windows: usuario={user} ip={ip or 'local'} tipo={ev.get('LogonType')}"
            category = "brute_force" if ev.get("LogonType") in ("3", "10", "8") else "auth_failure"
            return {
                "source": "windows_security",
                "event_id": 4625,
                "severity_hint": "high",
                "category_hint": category,
                "host": host,
                "user": user,
                "src_ip": ip,
                "logon_type": ev.get("LogonType"),
                "status": ev.get("Status"),
                "time": ts,
                "raw": summary,
                "message": summary,
            }

        if eid == 4624:
            # sucesso — so interessa logon de rede/remoto
            if str(ev.get("LogonType")) not in ("3", "10", "2", "7"):
                return None
            summary = f"Logon Windows bem-sucedido: usuario={user} ip={ip or 'local'} tipo={ev.get('LogonType')}"
            return {
                "source": "windows_security",
                "event_id": 4624,
                "severity_hint": "low",
                "category_hint": "authentication",
                "host": host,
                "user": user,
                "src_ip": ip,
                "logon_type": ev.get("LogonType"),
                "time": ts,
                "raw": summary,
                "message": summary,
            }
        return None