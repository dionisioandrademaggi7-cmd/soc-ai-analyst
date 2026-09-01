"""
Testes defensivos do alerter autónomo.

Alimentam linhas sintéticas de auth.log em alerter.handle_line.
Não abrem sockets, não fazem SSH, não chamam ufw real.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import alerter  # noqa: E402


FAIL = (
    "Sep  1 10:00:00 ubuntu sshd[1234]: Failed password for root from {ip} port 22 ssh2"
)
ACCEPT = (
    "Sep  1 10:00:00 ubuntu sshd[1234]: Accepted password for alice from {ip} port 22 ssh2"
)
INVALID = (
    "Sep  1 10:00:00 ubuntu sshd[1234]: Invalid user bob from {ip} port 22"
)
SUDO = (
    "Sep  1 10:00:00 ubuntu sudo: alice : USER=root ; COMMAND=/bin/id"
)


class AlerterTests(unittest.TestCase):
    def setUp(self):
        alerter.FAIL_THRESHOLD = 5
        alerter.WINDOW_SEC = 120
        alerter.COOLDOWN_SEC = 60
        alerter._alerts.clear()
        alerter._fail_times.clear()
        alerter._cooldown_until.clear()
        alerter._auto_block = False
        alerter._execute = False
        self._notify = patch.object(alerter, "_notify", lambda rec: None)
        self._notify.start()
        self.addCleanup(self._notify.stop)

    def _kinds(self):
        return [a["kind"] for a in alerter.get_alerts()]

    def _feed_fails(self, ip: str, n: int, notify: bool = True) -> None:
        line = FAIL.format(ip=ip)
        for _ in range(n):
            alerter.handle_line(line, notify=notify)

    def test_single_fail_fires_immediately(self):
        alerter.handle_line(FAIL.format(ip="203.0.113.10"), notify=True)
        self.assertEqual(self._kinds(), ["FAIL"])

    def test_invalid_and_sudo_fire_without_command(self):
        alerter.handle_line(INVALID.format(ip="203.0.113.11"), notify=True)
        alerter.handle_line(SUDO, notify=True)
        self.assertEqual(self._kinds(), ["INVALID", "SUDO"])

    def test_four_fails_are_four_fail_no_burst(self):
        self._feed_fails("203.0.113.10", 4, notify=True)
        self.assertEqual(self._kinds(), ["FAIL"] * 4)
        self.assertEqual(len(alerter._fail_times["203.0.113.10"]), 4)

    def test_fifth_fail_fires_fail_and_burst(self):
        ip = "203.0.113.10"
        self._feed_fails(ip, 5, notify=True)
        kinds = self._kinds()
        self.assertEqual(kinds.count("FAIL"), 5)
        self.assertEqual(kinds.count("BURST"), 1)
        self.assertEqual(kinds[-1], "BURST")
        self.assertIn("Triagem", alerter.get_alerts()[-1].get("next_step") or "")

    def test_accepted_from_non_whitelist_is_login(self):
        ip = "203.0.113.50"
        alerter.handle_line(ACCEPT.format(ip=ip), notify=True)
        alerts = alerter.get_alerts()
        self.assertEqual([a["kind"] for a in alerts], ["LOGIN"])
        self.assertEqual(alerts[0]["ip"], ip)

    def test_whitelist_127_001_ignored(self):
        self._feed_fails("127.0.0.1", 8, notify=True)
        alerter.handle_line(ACCEPT.format(ip="127.0.0.1"), notify=True)
        self.assertEqual(self._kinds(), [])
        self.assertNotIn("127.0.0.1", alerter._fail_times)

    def test_historical_notify_false_seeds_window_live_completes_burst(self):
        ip = "198.51.100.20"
        self._feed_fails(ip, 4, notify=False)
        self.assertEqual(self._kinds(), [])
        self.assertEqual(len(alerter._fail_times[ip]), 4)
        alerter.handle_line(FAIL.format(ip=ip), notify=True)
        self.assertEqual(self._kinds(), ["FAIL", "BURST"])

    def test_cooldown_second_burst_does_not_fire(self):
        ip = "203.0.113.77"
        self._feed_fails(ip, 5, notify=True)
        self.assertEqual(self._kinds().count("BURST"), 1)
        self._feed_fails(ip, 5, notify=True)
        self.assertEqual(self._kinds().count("BURST"), 1)
        self.assertEqual(self._kinds().count("FAIL"), 10)

    def test_login_still_allowed_after_burst(self):
        ip = "203.0.113.88"
        self._feed_fails(ip, 5, notify=True)
        alerter.handle_line(ACCEPT.format(ip=ip), notify=True)
        kinds = self._kinds()
        self.assertIn("BURST", kinds)
        self.assertEqual(kinds[-1], "LOGIN")

    def test_auto_block_lab_nat_10_0_2_15_never_calls_block(self):
        alerter._auto_block = True
        alerter._execute = True
        ip = "10.0.2.15"
        with patch.object(alerter, "block_ip") as mock_block:
            self._feed_fails(ip, 5, notify=True)
            mock_block.assert_not_called()
        alerts = alerter.get_alerts()
        bursts = [a for a in alerts if a["kind"] == "BURST"]
        self.assertEqual(len(bursts), 1)
        msg = (bursts[0].get("contain_result") or "").lower()
        self.assertTrue(msg)
        self.assertIn("recusado", msg)


if __name__ == "__main__":
    unittest.main()
