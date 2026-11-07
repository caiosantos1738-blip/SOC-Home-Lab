
from collections import defaultdict
from datetime import timedelta


# Detection thresholds (educational lab configuration)
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

SPRAY_USER_THRESHOLD = 5
SPRAY_WINDOW = timedelta(minutes=10)

SUSPICIOUS_LOGIN_THRESHOLD = 3
CORRELATION_WINDOW = timedelta(minutes=10)


# MITRE ATT&CK mappings
MITRE_MAPPINGS = {
    "SSH_BRUTE_FORCE": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access"
    },
    "SSH_PASSWORD_SPRAYING": {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "tactic": "Credential Access"
    },
    "SSH_FAILURES_FOLLOWED_BY_SUCCESS": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    }
}


def make_alert(rule_id, severity, description, events):
    """Build a standardized security alert with MITRE ATT&CK mapping."""

    mitre = MITRE_MAPPINGS[rule_id]

    return {
        "rule_id": rule_id,
        "severity": severity,
        "description": description,
        "source_ip": events[-1]["source_ip"],
        "event_count": len(events),
        "first_seen": events[0]["timestamp"].isoformat(),
        "last_seen": events[-1]["timestamp"].isoformat(),
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"]
    }


def detect_brute_force(events):
    """Detect repeated failed logins from one IP within five minutes."""

    grouped = defaultdict(list)

    for event in events:
        if event["event"] == "FAILED_LOGIN":
            grouped[event["source_ip"]].append(event)

    alerts = []

    for source_ip, failures in grouped.items():
        failures.sort(key=lambda item: item["timestamp"])

        for start in range(len(failures)):
            window_events = []

            for event in failures[start:]:
                if (
                    event["timestamp"] - failures[start]["timestamp"]
                    > BRUTE_FORCE_WINDOW
                ):
                    break

                window_events.append(event)

            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(make_alert(
                    "SSH_BRUTE_FORCE",
                    "HIGH",
                    "Repeated SSH authentication failures detected",
                    window_events
                ))
                break

    return alerts


def detect_password_spraying(events):
    """Detect failed logins targeting multiple users from one IP."""

    grouped = defaultdict(list)

    for event in events:
        if event["event"] == "FAILED_LOGIN":
            grouped[event["source_ip"]].append(event)

    alerts = []

    for source_ip, failures in grouped.items():
        failures.sort(key=lambda item: item["timestamp"])

        for start in range(len(failures)):
            window_events = []

            for event in failures[start:]:
                if (
                    event["timestamp"] - failures[start]["timestamp"]
                    > SPRAY_WINDOW
                ):
                    break

                window_events.append(event)

            unique_users = {
                event["username"] for event in window_events
            }

            if len(unique_users) >= SPRAY_USER_THRESHOLD:
                alerts.append(make_alert(
                    "SSH_PASSWORD_SPRAYING",
                    "HIGH",
                    "Multiple usernames targeted from one IP",
                    window_events
                ))
                break

    return alerts


def detect_suspicious_login(events):
    """Detect a successful login after repeated failures from the same IP."""

    grouped = defaultdict(list)

    for event in events:
        grouped[event["source_ip"]].append(event)

    alerts = []

    for source_ip, source_events in grouped.items():
        source_events.sort(key=lambda item: item["timestamp"])

        for index, event in enumerate(source_events):
            if event["event"] != "SUCCESSFUL_LOGIN":
                continue

            previous_failures = [
                previous
                for previous in source_events[:index]
                if previous["event"] == "FAILED_LOGIN"
                and timedelta(0)
                <= event["timestamp"] - previous["timestamp"]
                <= CORRELATION_WINDOW
            ]

            if len(previous_failures) >= SUSPICIOUS_LOGIN_THRESHOLD:
                alerts.append(make_alert(
                    "SSH_FAILURES_FOLLOWED_BY_SUCCESS",
                    "HIGH",
                    "Successful login followed repeated failures from same IP",
                    previous_failures + [event]
                ))

    return alerts


def run_detections(events):
    """Execute all detection rules."""

    alerts = []

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_password_spraying(events))
    alerts.extend(detect_suspicious_login(events))

    return alerts

