
import re
import csv
from pathlib import Path
from collections import Counter

# Configuration
INPUT_FILE = Path("evidence/ssh-auth.log")
OUTPUT_FILE = Path("reports/ssh-analysis.csv")
THRESHOLD = 3

# Local addresses used for test classification
LOCAL_IPS = {"127.0.0.1", "::1", "localhost"}

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)

SUCCESS_RE = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)


def anonymize(value, mapping, prefix):
    """Replace sensitive values with consistent pseudonyms."""
    if value not in mapping:
        mapping[value] = f"{prefix}_{len(mapping) + 1:03d}"
    return mapping[value]


def analyze():
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    username_map = {}
    ip_map = {}
    events = []
    failed_by_ip = Counter()

    with INPUT_FILE.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            parts = line.split(maxsplit=1)
            timestamp = parts[0] if parts else "unknown"

            failed = FAILED_RE.search(line)
            successful = SUCCESS_RE.search(line)

            match = failed or successful

            if not match:
                continue

            original_username = match.group("username")
            original_ip = match.group("ip")

            # Determine classification before anonymization
            if failed:
                event_type = "FAILED_LOGIN"
                failed_by_ip[original_ip] += 1
            else:
                event_type = "SUCCESSFUL_LOGIN"

            if original_ip in LOCAL_IPS:
                severity = "INFO"
                classification = "LOCAL_TEST"
            elif failed and failed_by_ip[original_ip] >= THRESHOLD:
                severity = "HIGH"
                classification = "REPEATED_FAILURES"
            elif failed:
                severity = "MEDIUM"
                classification = "FAILED_LOGIN"
            else:
                severity = "INFO"
                classification = "SUCCESSFUL_LOGIN"

            # Anonymize before storing or exporting
            safe_username = anonymize(
                original_username, username_map, "user"
            )

            safe_ip = anonymize(
                original_ip, ip_map, "192.0.2"
            )

            events.append({
                "timestamp": timestamp,
                "event": event_type,
                "username": safe_username,
                "source_ip": safe_ip,
                "severity": severity,
                "classification": classification
            })

    fields = [
        "timestamp",
        "event",
        "username",
        "source_ip",
        "severity",
        "classification"
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(events)

    failed_count = sum(
        event["event"] == "FAILED_LOGIN" for event in events
    )
    successful_count = sum(
        event["event"] == "SUCCESSFUL_LOGIN" for event in events
    )

    print("===== SSH SECURITY ANALYZER =====")
    print(f"Events analyzed: {len(events)}")
    print(f"Failed logins: {failed_count}")
    print(f"Successful logins: {successful_count}")
    print(f"Unique usernames anonymized: {len(username_map)}")
    print(f"Unique IPs anonymized: {len(ip_map)}")
    print(f"Report generated: {OUTPUT_FILE}")
    print("[OK] Sensitive values were anonymized.")


if __name__ == "__main__":
    analyze()

