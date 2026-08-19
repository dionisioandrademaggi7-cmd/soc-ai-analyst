"""
Cliente local que lê logs do sistema (principalmente auth.log)
e expõe a mesma interface do SplunkClient / MockSplunkClient.
"""
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class LocalLogClient:
    def __init__(self, *_, **__):
        self.auth_log = Path("/var/log/auth.log")

    def _read_lines(self, path: Path, max_lines: int = 2000) -> list[str]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.readlines()[-max_lines:]
        except PermissionError:
            return []

    def _parse_auth_line(self, line: str) -> Optional[dict]:
        line = line.strip()
        if not line:
            return None

        patterns = [
            (r"Failed password for (invalid user )?(\S+) from (\S+)", "failed_password"),
            (r"Invalid user (\S+) from (\S+)", "invalid_user"),
            (r"Accepted password for (\S+) from (\S+)", "accepted_password"),
            (r"sudo:.*?USER=(\S+).*?COMMAND=(.+)", "sudo"),
            (r"session opened for user (\S+)", "session_opened"),
        ]

        for regex, event_type in patterns:
            m = re.search(regex, line, re.IGNORECASE)
            if m:
                groups = m.groups()
                event = {
                    "_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sourcetype": "auth",
                    "raw": line,
                    "event_type": event_type,
                    "host": "ubuntu-lab",
                    "rule_name": event_type.replace("_", " ").title(),
                }

                if event_type in ("failed_password", "accepted_password"):
                    event["user"] = groups[1] if groups[0] else groups[0]
                    event["src_ip"] = groups[-1]
                elif event_type == "invalid_user":
                    event["user"] = groups[0]
                    event["src_ip"] = groups[1]
                elif event_type == "sudo":
                    event["user"] = groups[0]
                    event["command"] = groups[1]
                else:
                    event["user"] = groups[0] if groups else "unknown"

                return event
        return None

    def get_alerts(self, count: int = 50) -> list[dict]:
        lines = self._read_lines(self.auth_log)
        alerts = []

        for line in reversed(lines):
            event = self._parse_auth_line(line)
            if event:
                alerts.append(event)
                if len(alerts) >= count:
                    break

        if not alerts:
            for line in reversed(lines[-15:]):
                alerts.append({
                    "_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": "ubuntu-lab",
                    "sourcetype": "auth",
                    "rule_name": "Raw Auth Log",
                    "raw": line.strip(),
                })
                if len(alerts) >= count:
                    break

        return alerts

    def get_context_for_event(
        self,
        host: str = None,
        user: str = None,
        earliest_time: str = "-1h",
        latest_time: str = "+1h",
        max_count: int = 50,
    ) -> list[dict]:
        lines = self._read_lines(self.auth_log, max_lines=3000)
        events = []

        for line in reversed(lines):
            if user and user.lower() not in line.lower():
                continue
            event = self._parse_auth_line(line)
            if event:
                events.append(event)
            else:
                events.append({
                    "_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": host or "ubuntu-lab",
                    "user": user or "unknown",
                    "raw": line.strip(),
                    "sourcetype": "auth",
                })
            if len(events) >= max_count:
                break

        return events