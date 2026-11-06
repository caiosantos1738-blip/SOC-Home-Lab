import re
import csv
from collections import Counter

LOG_FILE = "evidence/ssh-auth.log"
OUTPUT_FILE = "reports/ssh-analysis.csv"

failed_pattern = re.compile(
    r"Failed password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
)

accepted_pattern = re.compile(
    r"Accepted password for "
    r"(?P<user>\S+) from (?P<ip>\S+)"
)

events = []
failed_ips = Counter()

with open(LOG_FILE, "r", errors="replace") as file:
    for line in file:
        failed = failed_pattern.search(line)
        accepted = accepted_pattern.search(line)

        if failed:
            user = failed.group("user")
            ip = failed.group("ip")

            events.append({
                "timestamp": line.split()[0],
                "event": "FAILED_LOGIN",
                "username": user,
                "source_ip": ip
            })

            failed_ips[ip] += 1

        elif accepted:
            user = accepted.group("user")
            ip = accepted.group("ip")

            events.append({
                "timestamp": line.split()[0],
                "event": "SUCCESSFUL_LOGIN",
                "username": user,
                "source_ip": ip
            })

with open(OUTPUT_FILE, "w", newline="") as file:
    fields = [
        "timestamp",
        "event",
        "username",
        "source_ip"
    ]

    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events)

print("===== SSH SECURITY ANALYZER =====")
print(f"Events analyzed: {len(events)}")

for ip, count in failed_ips.items():
    if count >= 3:
        classification = (
            "LOCAL TEST"
            if ip in ("127.0.0.1", "::1")
            else "REPEATED FAILURES"
        )

        print(f"[ALERT] IP: {ip}")
        print(f"Failed attempts: {count}")
        print(f"Classification: {classification}")

print(f"\nReport generated: {OUTPUT_FILE}")
