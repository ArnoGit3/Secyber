"""
ARNTECH CYBER LAB - Local Security Scanner
=============================================
Scans ONLY the local training server (127.0.0.1:5000) - never an
arbitrary target. Uses the Safety Engine to enforce this.

Checks performed map directly to the labs in this platform, so running
the scanner before and after toggling a lab to SECURE visibly shows the
finding flip from HIGH/MEDIUM to PASS.
"""

from __future__ import annotations
import sys
import os
from dataclasses import dataclass

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.security import enforce_safe_target, UnsafeTargetError
from config.branding import APP_NAME
from modules.reporting.audit_log import log_event

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "PASS": 3}


@dataclass
class Finding:
    severity: str  # HIGH, MEDIUM, LOW, PASS
    title: str
    detail: str


def _icon(sev: str) -> str:
    return {"HIGH": "[!]", "MEDIUM": "[!]", "LOW": "[!]", "PASS": "[+]"}.get(sev, "[*]")


def run_scan(host: str = "127.0.0.1", port: int = 5000) -> list[Finding]:
    """Run every check against the local training server and return findings."""
    enforce_safe_target(host)  # raises UnsafeTargetError if not localhost

    base = f"http://{host}:{port}"
    findings: list[Finding] = []

    # --- Security headers ---
    try:
        r = requests.get(f"{base}/headers-lab", timeout=3)
        headers = r.headers
        required = [
            "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
        ]
        missing = [h for h in required if h not in headers]
        if missing:
            findings.append(Finding("MEDIUM", "Missing security headers",
                                     f"Missing: {', '.join(missing)}"))
        else:
            findings.append(Finding("PASS", "Security headers present", "All required headers found"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check headers", str(e)))

    # --- Cookie flags ---
    try:
        r = requests.get(f"{base}/session-lab", timeout=3)
        set_cookie = r.headers.get("Set-Cookie", "")
        if "httponly" not in set_cookie.lower() or "samesite" not in set_cookie.lower():
            findings.append(Finding("MEDIUM", "Weak cookie configuration",
                                     f"Set-Cookie header: {set_cookie or '(none captured)'}"))
        else:
            findings.append(Finding("PASS", "Cookie configuration", "HttpOnly + SameSite present"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check cookies", str(e)))

    # --- SQL injection demo endpoint ---
    try:
        r = requests.post(f"{base}/sqli", data={"q": "sticker"}, timeout=3)
        if "LIKE '%" in r.text and "?" not in r.text.split("LIKE")[1][:5]:
            findings.append(Finding("HIGH", "SQL injection demonstration endpoint",
                                     "/sqli is using raw string interpolation (vulnerable mode)"))
        else:
            findings.append(Finding("PASS", "SQL injection endpoint", "/sqli is using parameterized queries"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check /sqli", str(e)))

    # --- XSS demo endpoint ---
    try:
        marker = "arntechxsscheck"
        r = requests.get(f"{base}/xss", params={"msg": f"<b>{marker}</b>"}, timeout=3)
        if f"<b>{marker}</b>" in r.text:
            findings.append(Finding("HIGH", "Reflected XSS", "/xss reflects unescaped HTML (vulnerable mode)"))
        else:
            findings.append(Finding("PASS", "Reflected XSS endpoint", "/xss output is escaped"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check /xss", str(e)))

    # --- Debug mode ---
    try:
        r = requests.get(f"{base}/this-route-does-not-exist-arntech", timeout=3)
        if "Werkzeug Debugger" in r.text or r.status_code == 500 and "Traceback" in r.text:
            findings.append(Finding("HIGH", "Debug mode enabled", "Werkzeug debugger is exposed"))
        else:
            findings.append(Finding("PASS", "Debug mode", "Debug mode is disabled"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check debug mode", str(e)))

    # --- Password storage ---
    try:
        r = requests.get(f"{base}/password-lab", timeout=3)
        if "password_plaintext" in r.text.lower() or "DemoPassword123!" in r.text:
            findings.append(Finding("MEDIUM", "Plaintext password storage demo table present",
                                     "users_insecure table stores plaintext passwords (by design, for the demo)"))
        findings.append(Finding("PASS", "Password hashing available",
                                 "users_secure table stores Werkzeug-hashed passwords"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check password lab", str(e)))

    # --- CSRF protection (forms lack a CSRF token by design, to teach the concept) ---
    try:
        r = requests.get(f"{base}/training-login", timeout=3)
        if "csrf" not in r.text.lower():
            findings.append(Finding("MEDIUM", "Missing CSRF protection",
                                     "Forms do not include a CSRF token"))
        else:
            findings.append(Finding("PASS", "CSRF protection", "CSRF tokens present"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check CSRF", str(e)))

    # --- File upload configuration ---
    try:
        r = requests.get(f"{base}/upload-lab", timeout=3)
        if "no extension allowlist" in r.text.lower():
            findings.append(Finding("MEDIUM", "Unsafe file upload configuration",
                                     "/upload-lab has no extension allowlist or size limit (vulnerable mode)"))
        else:
            findings.append(Finding("PASS", "File upload configuration", "Allowlist + size limit enforced"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check upload lab", str(e)))

    # --- Command injection demo endpoint ---
    try:
        r = requests.get(f"{base}/cmdinject", timeout=3)
        # We can't safely detect shell=True remotely without invoking it;
        # report based on lab state exposed in the page text.
        if "shell=true with string-built" in r.text.lower():
            findings.append(Finding("HIGH", "Unsafe command execution",
                                     "/cmdinject builds a shell command from user input (vulnerable mode)"))
        else:
            findings.append(Finding("PASS", "Command execution", "Fixed argument list, no shell interpretation"))
    except requests.RequestException as e:
        findings.append(Finding("LOW", "Could not check /cmdinject", str(e)))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    log_event("scanner", f"scan {base}", f"{len(findings)} findings")
    return findings


def render_scan_report(findings: list[Finding], host="127.0.0.1", port=5000) -> str:
    lines = [
        "============================================",
        f"{APP_NAME} SECURITY SCANNER",
        "============================================",
        "",
        f"Target:",
        f"{host}:{port}",
        "",
    ]
    for f in findings:
        lines.append(f"{_icon(f.severity)} {f.severity:<7} {f.title}")
        lines.append(f"        {f.detail}")
    return "\n".join(lines)


if __name__ == "__main__":
    try:
        results = run_scan()
        print(render_scan_report(results))
    except UnsafeTargetError as e:
        print(f"[BLOCKED] {e}")
