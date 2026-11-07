# Advanced Security Log Analyzer

A Python-based security log analysis tool designed to identify suspicious SSH authentication activities through automated detection rules, event correlation, MITRE ATT&CK mapping, and security alert generation.

This project is part of a hands-on cybersecurity portfolio focused on **SOC Analyst, Blue Team, and Security Monitoring** skills.

## Project Overview

The Advanced Security Log Analyzer processes SSH authentication logs, extracts structured security events, identifies suspicious activity, and generates sanitized reports.

The detection engine currently supports three security scenarios:

- **SSH Brute Force:** Detects repeated failed authentication attempts from the same source IP.
- **Password Spraying:** Identifies attempts involving multiple usernames from the same source IP.
- **Suspicious Login:** Detects successful authentication following multiple failed login attempts.

Security alerts are enriched with MITRE ATT&CK technique information. Sensitive information, including usernames and source IP addresses, is pseudonymized before report generation.

## Features

- SSH authentication log parsing.
- Support for ISO and traditional syslog timestamps.
- Automated security event classification.
- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Time-window-based event correlation.
- MITRE ATT&CK technique mapping.
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
| Unittest | Automated testing |
| Linux / Ubuntu | Development environment |
| Git / GitHub | Version control |

**Dependencies:** The project uses Python standard library modules and does not require external Python packages.

## Detection Rules

| Detection Rule | Detection Criteria | Severity |
|---|---|---|
| SSH Brute Force | 5 failed attempts within 5 minutes | HIGH |
| Password Spraying | 5 or more distinct usernames within 10 minutes from the same IP | HIGH |
| Suspicious Login | Successful login following at least 3 failed attempts within 10 minutes | HIGH |

These thresholds are configurable and intended for educational security monitoring. An alert indicates suspicious behavior, not definitive proof of a successful attack.

## MITRE ATT&CK Integration

The detection engine enriches generated alerts with MITRE ATT&CK technique identifiers, names, and tactics.

| Detection Rule | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| SSH Brute Force | T1110.001 | Password Guessing | Credential Access |
| Password Spraying | T1110.003 | Password Spraying | Credential Access |
| Suspicious Login | T1110 | Brute Force | Credential Access |

The suspicious login mapping represents a behavioral correlation involving repeated authentication failures followed by a successful login. It does not independently confirm account compromise.

## Project Architecture

```text
soc-lab/
│
├── evidence/
│   └── ssh-auth.log
│
├── reports/
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

The parser reads SSH authentication logs and extracts:

- Timestamp
- Event type
- Username
- Source IP address

**2. Event Processing**

Authentication records are converted into structured Python dictionaries.

**3. Threat Detection and MITRE Mapping**

The detection engine evaluates authentication events using configurable thresholds and time windows. When suspicious behavior is identified, the corresponding MITRE ATT&CK information is attached to the alert.

**4. Report Generation**

The analyzer generates two output files:

| File | Description |
|---|---|
| `ssh-analysis.csv` | Sanitized authentication event report |
| `security-alerts.json` | Security alerts enriched with MITRE ATT&CK metadata |

## Installation

Clone the repository:

```bash
git clone https://github.com/caiosantos1738-blip/SOC-Home-Lab.git
```

Navigate to the project directory:

```bash
cd soc-lab
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
python3 -m unittest discover -v
```

The current test suite validates:

- Brute force detection.
- Password spraying detection.
- Suspicious login detection.
- Behavior below detection thresholds.
- MITRE ATT&CK mapping for all three detection rules.
- Complete analysis pipeline and report generation.
- Data anonymization during report export.

**Current validation: 8 automated tests passed.**

## Example Detection Alert

A simulated brute force scenario involving five failed SSH authentication attempts within two minutes generated the following alert:

```json
{
    "rule_id": "SSH_BRUTE_FORCE",
    "severity": "HIGH",
    "description": "Repeated SSH authentication failures detected",
    "source_ip": "IP_001",
    "event_count": 5,
    "first_seen": "2026-11-06T14:00:00+00:00",
    "last_seen": "2026-11-06T14:02:00+00:00",
    "mitre_technique_id": "T1110.001",
    "mitre_technique_name": "Password Guessing",
    "mitre_tactic": "Credential Access"
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

- Linux security log analysis.
- Python scripting and automation.
- SSH authentication monitoring.
- Security event correlation.
- Detection engineering fundamentals.
- MITRE ATT&CK framework fundamentals.
- Incident detection and alert classification.
- Data sanitization.
- Automated software testing.
- Git and GitHub workflows.

## Future Improvements

- Add Windows Event Log analysis.
- Implement additional detection rules.
- Improve alert correlation and deduplication.
- Add configurable detection thresholds.
- Improve timestamp and timezone handling.
- Generate visual security dashboards.
- Expand automated test coverage.

## Disclaimer

This project is intended for educational purposes and cybersecurity portfolio development. Detection results are based on heuristic rules and should be investigated before being treated as confirmed security incidents.

---

**Developed as a cybersecurity portfolio project focused on SOC Analysis and Blue Team operations.**
