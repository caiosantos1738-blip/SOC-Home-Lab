
import unittest
from datetime import datetime, timedelta, timezone

from src.detection import run_detections


class DetectionTests(unittest.TestCase):

    def setUp(self):
        self.base_time = datetime(
            2026, 11, 6, 10, 0, tzinfo=timezone.utc
        )

    def create_event(self, minutes, event_type, username, ip):
        return {
            "timestamp": self.base_time + timedelta(minutes=minutes),
            "event": event_type,
            "username": username,
            "source_ip": ip
        }

    def test_brute_force_detection(self):
        events = [
            self.create_event(
                i, "FAILED_LOGIN", "admin", "192.0.2.10"
            )
            for i in range(5)
        ]

        alerts = run_detections(events)

        self.assertTrue(
            any(a["rule_id"] == "SSH_BRUTE_FORCE" for a in alerts)
        )

    def test_password_spraying_detection(self):
        users = ["admin", "root", "guest", "user1", "support"]

        events = [
            self.create_event(
                i, "FAILED_LOGIN", user, "192.0.2.20"
            )
            for i, user in enumerate(users)
        ]

        alerts = run_detections(events)

        self.assertTrue(
            any(
                a["rule_id"] == "SSH_PASSWORD_SPRAYING"
                for a in alerts
            )
        )

    def test_suspicious_login_detection(self):
        events = [
            self.create_event(
                i, "FAILED_LOGIN", "admin", "192.0.2.30"
            )
            for i in range(3)
        ]

        events.append(
            self.create_event(
                4, "SUCCESSFUL_LOGIN", "admin", "192.0.2.30"
            )
        )

        alerts = run_detections(events)

        self.assertTrue(
            any(
                a["rule_id"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
                for a in alerts
            )
        )

    def test_no_alert_below_threshold(self):
        events = [
            self.create_event(
                i, "FAILED_LOGIN", "admin", "192.0.2.40"
            )
            for i in range(3)
        ]

        alerts = run_detections(events)

        self.assertEqual(alerts, [])

    # MITRE ATT&CK mapping tests

    def test_brute_force_mitre_mapping(self):
        events = [
            self.create_event(
                i, "FAILED_LOGIN", "admin", "192.0.2.50"
            )
            for i in range(5)
        ]

        alerts = run_detections(events)

        alert = next(
            a for a in alerts
            if a["rule_id"] == "SSH_BRUTE_FORCE"
        )

        self.assertEqual(alert["mitre_technique_id"], "T1110.001")
        self.assertEqual(
            alert["mitre_technique_name"], "Password Guessing"
        )
        self.assertEqual(alert["mitre_tactic"], "Credential Access")

    def test_password_spraying_mitre_mapping(self):
        users = ["admin", "root", "guest", "user1", "support"]

        events = [
            self.create_event(
                i, "FAILED_LOGIN", user, "192.0.2.60"
            )
            for i, user in enumerate(users)
        ]

        alerts = run_detections(events)

        alert = next(
            a for a in alerts
            if a["rule_id"] == "SSH_PASSWORD_SPRAYING"
        )

        self.assertEqual(alert["mitre_technique_id"], "T1110.003")
        self.assertEqual(
            alert["mitre_technique_name"], "Password Spraying"
        )
        self.assertEqual(alert["mitre_tactic"], "Credential Access")

    def test_suspicious_login_mitre_mapping(self):
        events = [
            self.create_event(
                i, "FAILED_LOGIN", "admin", "192.0.2.70"
            )
            for i in range(3)
        ]

        events.append(
            self.create_event(
                4, "SUCCESSFUL_LOGIN", "admin", "192.0.2.70"
            )
        )

        alerts = run_detections(events)

        alert = next(
            a for a in alerts
            if a["rule_id"] == "SSH_FAILURES_FOLLOWED_BY_SUCCESS"
        )

        self.assertEqual(alert["mitre_technique_id"], "T1110")
        self.assertEqual(
            alert["mitre_technique_name"], "Brute Force"
        )
        self.assertEqual(alert["mitre_tactic"], "Credential Access")


if __name__ == "__main__":
    unittest.main(verbosity=2)
