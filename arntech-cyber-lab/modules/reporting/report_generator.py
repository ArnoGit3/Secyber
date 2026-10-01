"""
ARNTECH ENTERPRISE CYBER LAB - Commercial Security Report Generator
==================================================================
Generates reports/ARNTECH_CYBER_LAB_SECURITY_REPORT.html - a self-contained,
executive-ready commercial HTML security audit report.
"""

from __future__ import annotations
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.branding import APP_NAME, SUBTITLE, AUTHOR, VERSION, DISCLAIMER
from modules.scanner.scanner import run_scan, Finding

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
REPORT_PATH = os.path.join(REPORTS_DIR, "ARNTECH_CYBER_LAB_SECURITY_REPORT.html")

MODULES_TESTED = [
    "Reconnaissance & Asset Mapping", "Phishing & Credential Security", "Email Domain & Header Security",
    "Website Cloning & Brand Protection", "Commercial Payment Gateway & Carding Audit",
    "SQL Injection Security Audit", "Cross-Site Scripting (XSS) Audit", "Command Injection Audit",
    "Authentication Policy & Rate Limiting", "Cryptographic Password Storage", "Session & Cookie Security",
    "HTTP Security Headers Audit", "File Upload Security Policy", "REST API Security & Key Authorization",
]

SEVERITY_COLOR = {"HIGH": "#f43f5e", "MEDIUM": "#f59e0b", "LOW": "#64748b", "PASS": "#10b981"}


def _findings_rows(findings: list[Finding]) -> str:
    rows = []
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "#ccc")
        rows.append(
            f"<tr><td style='color:{color}; font-weight:bold;'>{f.severity}</td>"
            f"<td style='font-weight:600; color:#fff;'>{f.title}</td><td>{f.detail}</td></tr>"
        )
    return "\n".join(rows)


def generate_report(host: str = "127.0.0.1", port: int = 5000) -> str:
    findings = run_scan(host, port)
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    passed = sum(1 for f in findings if f.severity == "PASS")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{APP_NAME} - Commercial Security Audit Report</title>
<style>
  body {{ background:#070b12; color:#e2e8f0; font-family: 'Inter', system-ui, sans-serif; margin:0; padding:0; line-height:1.6; }}
  header {{ background:#0d131f; border-bottom:1px solid #1e2c40; padding:30px; text-align:center; }}
  h1 {{ color:#00f2fe; margin:0; font-size:26px; letter-spacing:1px; }}
  .subtitle {{ color:#94a3b8; margin-top:6px; font-size:14px; }}
  main {{ max-width:960px; margin:32px auto; padding:0 24px 60px; }}
  .panel {{ background:#111a28; border:1px solid #1e2c40; border-radius:10px; padding:24px; margin-bottom:24px; }}
  .panel h2 {{ color:#ffffff; font-size:18px; border-bottom:1px solid #1e2c40; padding-bottom:10px; margin-top:0; }}
  table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
  th, td {{ text-align:left; padding:10px 14px; border-bottom:1px solid #1e2c40; font-size:13.5px; vertical-align:top; }}
  th {{ color:#94a3b8; font-size:12px; text-transform:uppercase; background:#0d131f; }}
  .summary-badges span {{ display:inline-block; margin-right:14px; padding:8px 16px; border-radius:20px; font-weight:bold; font-size:13px; }}
  .disclaimer {{ font-size:12.5px; color:#64748b; border-top:1px solid #1e2c40; padding-top:14px; margin-top:14px; }}
</style>
</head>
<body>
<header>
  <h1>{APP_NAME}</h1>
  <div class="subtitle">{SUBTITLE}</div>
  <div class="subtitle">Version {VERSION} &middot; {AUTHOR} &middot; Audit Timestamp {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</header>
<main>

<div class="panel">
  <h2>Executive Summary</h2>
  <p>{APP_NAME} is a commercial cybersecurity audit and threat simulation platform. It performs automated security scans, payment gateway authorization audits, carding vulnerability checks, and security rule evaluation against enterprise web applications and API endpoints.</p>
</div>

<div class="panel">
  <h2>Testing Environment Scope</h2>
  <table>
    <tr><th>Target Infrastructure</th><td>{host}:{port} (Local Enterprise Cyber Lab Network)</td></tr>
    <tr><th>Security Mode</th><td>Commercial Audit & Compliance Verification</td></tr>
    <tr><th>Gateway Auditor</th><td>Luhn Modulo-10 Checksum, BIN Lookup Engine, ISO 8583 Gateway Protocol</td></tr>
  </table>
</div>

<div class="panel">
  <h2>Security Audit Modules Evaluated</h2>
  <ul>
    {''.join(f'<li>{m}</li>' for m in MODULES_TESTED)}
  </ul>
</div>

<div class="panel">
  <h2>Vulnerability Summary Metrics</h2>
  <div class="summary-badges">
    <span style="background:rgba(244,63,94,0.15); color:#f43f5e; border:1px solid #f43f5e;">HIGH RISK: {high}</span>
    <span style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid #f59e0b;">MEDIUM RISK: {medium}</span>
    <span style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid #10b981;">PASSED: {passed}</span>
  </div>
</div>

<div class="panel">
  <h2>Audit Findings & Technical Evidence</h2>
  <table>
    <tr><th>Severity</th><th>Finding Title</th><th>Evidence / Detail</th></tr>
    {_findings_rows(findings)}
  </table>
</div>

<div class="panel">
  <h2>Commercial Remediation Recommendations</h2>
  <ul>
    <li>Enforce prepared statements (parameterized queries) across all SQL database access layers.</li>
    <li>Apply contextual HTML entity encoding and strict Content-Security-Policy rules to prevent XSS.</li>
    <li>Pass binary process calls as fixed argument arrays, avoiding raw shell concatenation.</li>
    <li>Implement Luhn validation, BIN risk score filtering, 3-D Secure, and tokenization on payment gateways.</li>
    <li>Hash passwords with slow salted algorithms (PBKDF2/bcrypt/Argon2).</li>
    <li>Set HttpOnly, SameSite, and Secure flags on session cookies.</li>
  </ul>
</div>

<div class="panel">
  <h2>System Governance & Ethical Boundaries</h2>
  <p class="disclaimer">{DISCLAIMER}</p>
</div>

</main>
</body>
</html>
"""
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    return REPORT_PATH


if __name__ == "__main__":
    path = generate_report()
    print(f"Report generated: {path}")
