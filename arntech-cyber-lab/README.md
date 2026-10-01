# ARNTECH CYBER LAB

**Enterprise Cyber Security & Commercial Payment Gateway Audit Suite**

> Attack • Detect • Analyze • Defend

An enterprise-grade, commercial cybersecurity platform built for vulnerability auditing, carding security validation, and payment gateway threat testing within a secured lab environment.

See [ETHICS.md](ETHICS.md) for the complete ethical-use and system boundary statement.

---

## Overview

Every module in this platform follows a rigorous enterprise audit methodology:

1. **Vulnerability Audit** & Target Surface Analysis
2. **Threat Simulation** & Execution
3. **Telemetry & Log Analysis**
4. **Impact Assessment**
5. **Remediation & Hardening Controls**
6. **Automated Verification Scan**
7. **Compliance & Audit Reporting**

---

## Architecture

```
arntech-cyber-lab/
│
├── cli.py                   Main entry point / interactive CLI audit console
├── requirements.txt         Python dependencies
├── install.sh               Setup script
├── README.md                Documentation
├── ETHICS.md                System security policy
│
├── config/
│   ├── branding.py           Branding and enterprise configuration
│   └── security.py           Safety Control Engine
│
├── modules/
│   ├── payment_phishing/
│   │   └── card_processor.py Card processor, Luhn algorithm, & BIN lookup engine
│   ├── reporting/
│   │   ├── audit_log.py       Audit logger
│   │   └── report_generator.py  Executive HTML security report generator
│   └── scanner/
│       └── scanner.py          Automated local vulnerability scanner
│
├── lab_server/
│   ├── app.py                Flask audit server — vulnerable/hardened endpoints
│   ├── database.py           SQLite database schema & audit log tables
│   ├── templates/            HTML dashboards for security modules
│   └── static/css/style.css  Dark futuristic enterprise styling
│
├── data/
│   ├── lab.db                 SQLite database
│   ├── uploads/               Uploaded file storage
│   └── logs/lab.log           Audit logs
│
└── reports/
    └── ARNTECH_CYBER_LAB_SECURITY_REPORT.html   Generated security audit report
```

---

## Key Features & Capabilities

- **Commercial Payment Gateway & Carding Audit Laboratory:**
  - Real-time **Modulo-10 (Luhn) Checksum Validation**
  - **BIN Lookup Engine:** Instant bank identification, card network brand (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners Club, Maestro), card level (Infinite, World Elite, Signature, Platinum, Gold), card type (Credit/Debit/Prepaid), issuer country, and currency.
  - **Simulated Payment Gateway Authorization Engine:** Full ISO 8583 / REST API payment processing simulation returning status (`APPROVED`, `DECLINED_INVALID_CARD_NUMBER`, `DECLINED_LUHN_CHECKSUM_FAILURE`, `DECLINED_EXPIRED_CARD`, `DECLINED_INVALID_CVV`, `DECLINED_INSUFFICIENT_FUNDS`, `DECLINED_SUSPECTED_FRAUD`), authorization codes, transaction IDs, latency, and risk scoring (0-100).
  - Live AJAX BIN Inspector API endpoint (`/api/bin-lookup`).
- **Web Application & API Vulnerability Suite:**
  - SQL Injection (Prepared Statements vs String Interpolation)
  - Cross-Site Scripting (Reflected & Stored XSS Encoding)
  - Subprocess Command Injection (Fixed Argument Arrays)
  - Authentication Brute-Force & Rate Limiting Lockout
  - Cryptographic Password Storage (Salted Hashes vs Plaintext)
  - Session Cookie Flag Hardening (HttpOnly, SameSite, Secure)
  - HTTP Security Headers (CSP, HSTS, X-Frame-Options, Nosniff)
  - File Upload Policy & Extension Allowlisting
  - REST API Security & Header Key Authorization

---

## Quick Start

```bash
python3 cli.py
```

Arguments:
- `python3 cli.py --serve` : Start the audit web server only (`http://127.0.0.1:5000`)
- `python3 cli.py --audit-suite` : Run the Executive Security Audit Suite
- `python3 cli.py --scan` : Run the automated security scanner
- `python3 cli.py --report` : Generate the HTML security audit report
- `python3 cli.py --reset-lab` : Reset database and system logs
