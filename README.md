HEAD
Practical cybersecurity laboratory focused on Security Operations Center (SOC), defensive security, and threat detection.

# Advanced Security Log Analyzer

A Python-based security log analysis tool designed to identify suspicious SSH authentication activities through automated detection rules, event correlation, and security alert generation.

This project was developed as a hands-on cybersecurity portfolio project focused on **SOC Analyst, Blue Team, and Security Monitoring** skills.

## Project Overview

The Advanced Security Log Analyzer processes SSH authentication logs, extracts structured security events, identifies suspicious activity, and generates sanitized reports.

The detection engine currently supports three security scenarios:

- **SSH Brute Force:** Detects repeated failed authentication attempts from the same source IP.
- **Password Spraying:** Identifies attempts involving multiple usernames from the same source IP.
- **Suspicious Login:** Detects successful authentication following multiple failed login attempts.

Sensitive information, including usernames and source IP addresses, is anonymized before report generation.

## Features

- SSH authentication log parsing.
- Support for ISO and traditional syslog timestamps.
- Automated security event classification.
- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Time-window-based event correlation.
- Username and IP address pseudonymization.
- CSV security event reports.
- JSON security alert reports.
- Unit and integration testing.

## Technologies

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| Regular Expressions | Log parsing |
| CSV | Security event reporting |
| JSON | Alert reporting |
| IP Address Module | IP validation |
| Unittest | Automated testing |
| Linux / Ubuntu | Development environment |
| Git / GitHub | Version control |

**Dependencies:** The project currently uses Python standard library modules and does not require external Python packages.

## Detection Rules

| Detection Rule | Detection Criteria | Severity |
|---|---|---|
| SSH Brute Force | 5 failed login attempts within 5 minutes | HIGH |
| Password Spraying | 5 or more distinct usernames within 10 minutes from the same IP | HIGH |
| Suspicious Login | Successful login following at least 3 failed attempts within 10 minutes | HIGH |

These thresholds are configurable and intended for educational security monitoring. An alert indicates suspicious behavior, not definitive proof of a successful attack.

## Project Architecture

```text
Advanced-Security-Log-Analyzer/
│
├── architecture/
│
├── documentation/
│
├── evidence/
│
├── reports/
│
├── screenshots/
│
├── scripts/
│
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── parser.py
│   └── detection.py
│
├── tests/
│   ├── fixtures/
│   │   └── brute_force.log
│   ├── test_detection.py
│   └── test_integration.py
│
├── .gitignore
└── README.md
```

## How It Works

The analysis pipeline follows four main stages:

**1. Log Collection and Parsing**

The parser reads SSH authentication logs and extracts relevant information:

- Timestamp
- Event type
- Username
- Source IP address

**2. Event Processing**

Authentication records are converted into structured Python dictionaries.

**3. Threat Detection**

The detection engine evaluates authentication events using configurable thresholds and time windows.

**4. Report Generation**

The analyzer generates two output files:

| File | Description |
|---|---|
| `ssh-analysis.csv` | Sanitized authentication event report |
| `security-alerts.json` | Generated security alerts |

## Installation

Clone the repository:

```bash
git clone https://github.com/caiosantos1738-blip/Advanced-Security-Log-Analyzer.git
```

Navigate to the project directory:

```bash
cd Advanced-Security-Log-Analyzer
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

No additional Python packages are required.

## Usage

Place your SSH authentication log at:

```text
evidence/ssh-auth.log
```

Run the analyzer from the project root:

```bash
python3 -m src.analyzer
```

Generated reports will be saved in:

```text
reports/
├── ssh-analysis.csv
└── security-alerts.json
```

## Running Tests

Execute the automated test suite:

```bash
python3 -m unittest discover -s tests -v
```

The current test suite covers:

- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Behavior below detection thresholds.
- End-to-end analysis and report generation.

**Current validation:** 5 automated tests passed.

## Example Detection Output

A simulated brute force scenario involving five failed SSH authentication attempts within two minutes generated the following alert:

```json
{
    "rule_id": "SSH_BRUTE_FORCE",
    "severity": "HIGH",
    "description": "Repeated SSH authentication failures detected",
    "source_ip": "IP_001",
    "event_count": 5,
    "first_seen": "2026-11-06T14:00:00+00:00",
    "last_seen": "2026-11-06T14:02:00+00:00"
}
```

The example uses a pseudonymized IP address and simulated authentication events.

## Security and Privacy

- Usernames and source IP addresses are pseudonymized in generated reports.
- Test fixtures use fictitious authentication records.
- Raw authentication logs should not be committed to public repositories.
- This project is intended for educational and controlled laboratory environments.

**Important:** Pseudonymization reduces exposure of sensitive information but does not guarantee complete anonymity. Review all files before publishing.

## Skills Demonstrated

This project demonstrates practical experience with:

- Linux security log analysis.
- Python scripting and automation.
- SSH authentication monitoring.
- Security event correlation.
- Detection engineering fundamentals.
- Incident detection and alert classification.
- Data sanitization.
- Automated software testing.
- Git and GitHub workflows.

## Future Improvements

- Add Windows Event Log analysis.
- Implement additional detection rules.
- Integrate MITRE ATT&CK technique mapping.
- Improve alert correlation and deduplication.
- Add configurable detection thresholds.
- Generate visual security dashboards.
- Expand automated test coverage.

## Disclaimer

This project is intended for educational purposes and cybersecurity portfolio development. Detection results are based on heuristic rules and should be investigated before being treated as confirmed security incidents.

---

**Developed as a cybersecurity portfolio project focused on SOC Analysis and Blue Team operations.**
>>>>>>> a8191ca (Build advanced security log analyzer)
