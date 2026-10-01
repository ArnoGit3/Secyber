"""
ARNTECH CYBER LAB - Enterprise Security Branding Configuration
==============================================================
Central place to customize all branding, naming, and display text
used throughout the platform (CLI, reports, HTML pages, logs).
"""

import sys

# Ensure UTF-8 output encoding for Windows stdout
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

APP_NAME = "ARNTECH CYBER LAB"
SHORT_NAME = "ARNTECH"
TAGLINE = "Enterprise Cyber Security & Payment Gateway Audit Suite"
SUBTITLE = "Commercial Vulnerability Assessment, Gateway Security Auditor & Threat Defense Platform"
AUTHOR = "ARNTECH Cyber Security"
VERSION = "2.0.0 Enterprise"

LAB_MODE = True

ENVIRONMENT_LABEL = "SECURE ENTERPRISE SECURITY LAB"
MODE_LABEL = "COMMERCIAL / AUDIT & DEFENSE"
TARGET_LABEL = "LOCALHOST LAB NETWORK"

FICTIONAL_UNIVERSITY = "ARNTECH ENTERPRISE SYSTEMS"
FICTIONAL_UNIVERSITY_DOMAIN = "arntech-security.internal"
FICTIONAL_BANK = "ARNTECH ENTERPRISE PAYMENT GATEWAY"
FICTIONAL_EMAIL_DOMAIN = "arntech-labs.internal"

MAIN_BANNER = r"""
+------------------------------------------------------------------+
|                                                                  |
|                 ARNTECH CYBER LAB                                |
|      ENTERPRISE AUDIT & PAYMENT GATEWAY SUITE                    |
|                                                                  |
|      Vulnerability Assessment * Gateway Audit * Defense          |
|                                                                  |
+------------------------------------------------------------------+
"""

STATUS_ICONS = {
    "safe": "[+] SECURE",
    "warning": "[!] WARNING",
    "vulnerable": "[-] VULNERABLE",
    "info": "[*] INFORMATION",
    "fixed": "[OK] AUDITED & FIXED",
}

DISCLAIMER = (
    "This commercial security environment operates in a controlled, isolated "
    "cybersecurity lab environment against local systems and targeted authorization endpoints. "
    "All security audits, BIN lookups, Luhn validations, and payment gateway responses are "
    "executed within the secured sandbox system."
)
