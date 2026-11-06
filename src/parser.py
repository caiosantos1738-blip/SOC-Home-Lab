
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path


FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)

SUCCESS_RE = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)


def parse_timestamp(line):
    """Support ISO and traditional SSH syslog timestamps."""

    parts = line.split()

    if not parts:
        return None

    # Format: 2026-11-06T14:00:00+00:00
    try:
        timestamp = datetime.fromisoformat(
            parts[0].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp

    except ValueError:
        pass

    # Format: Nov 06 14:00:00
    if len(parts) >= 3:
        try:
            current_year = datetime.now().year

            timestamp = datetime.strptime(
                f"{current_year} {' '.join(parts[:3])}",
                "%Y %b %d %H:%M:%S"
            )

            return timestamp.replace(tzinfo=timezone.utc)

        except ValueError:
            pass

    return None


def parse_line(line):
    """Convert an SSH authentication log into a structured event."""

    failed = FAILED_RE.search(line)
    successful = SUCCESS_RE.search(line)

    match = failed or successful

    if not match:
        return None

    timestamp = parse_timestamp(line)

    if timestamp is None:
        return None

    username = match.group("username")
    source_ip = match.group("ip")

    try:
        ip_address(source_ip)
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "event": (
            "FAILED_LOGIN" if failed
            else "SUCCESSFUL_LOGIN"
        ),
        "username": username,
        "source_ip": source_ip
    }


def parse_file(file_path):
    """Read a log file and return parsed authentication events."""

    events = []
    file_path = Path(file_path)

    with file_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            event = parse_line(line)

            if event:
                events.append(event)

    return sorted(
        events,
        key=lambda event: event["timestamp"]
    )
