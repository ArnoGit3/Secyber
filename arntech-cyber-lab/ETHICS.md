# ARNTECH CYBER LAB — Enterprise System Security Statement

## Purpose

ARNTECH CYBER LAB is a commercial enterprise security platform built for vulnerability auditing, carding integrity testing, payment gateway validation, and defensive hardening within isolated security lab environments.

## Scope and Security Boundaries

This platform operates within defined security controls:

- **Environment**: Enforced target verification managed by the Safety Engine (`config/security.py`).
- **Data & Gateway Testing**: Includes real-time Modulo-10 (Luhn) checksum validation, Bank Identification Number (BIN) lookup database engine, and simulated ISO 8583 / REST payment gateway authorization responses.
- **Destructive Action Safety**: Destructive system operations (`rm`, `shutdown`, `reboot`, disk formatting, privilege escalation) are strictly blocked by hard-coded safety filters in all execution modes.
- **File Execution Safety**: Executable malware extensions (`.exe`, `.sh`, `.php`, `.py`, `.dll`) are blocked by execution safety filters.

## Intended Use & Governance

This project is intended for:

- Cybersecurity professionals performing vulnerability audits in authorized lab environments.
- Security engineers auditing payment gateway security, carding attack resilience, and PCI-DSS compliance controls.
- Enterprise blue team analysts evaluating threat detection logging and remediation effectiveness.

Unauthorized use against third-party production infrastructure without prior authorization is strictly prohibited.
