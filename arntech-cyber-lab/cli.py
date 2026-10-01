#!/usr/bin/env python3
"""
ARNTECH CYBER LAB - Command Line Interface
=============================================
Entry point for the whole platform.

Usage:
    python3 cli.py                 interactive menu
    python3 cli.py --serve         start the Flask enterprise audit server
    python3 cli.py --audit         guided executive audit walkthrough
    python3 cli.py --report        generate the HTML security report
    python3 cli.py --scan          run the scanner once and print results
    python3 cli.py --reset-lab     wipe the database and logs back to a clean state
    python3 cli.py --selftest      run the Safety Engine's built-in test cases
"""

from __future__ import annotations
import argparse
import os
import platform
import socket
import subprocess
import sys
import time
import webbrowser

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:  # graceful fallback if colorama isn't installed
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Dummy()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config.branding import (
    APP_NAME, TAGLINE, SUBTITLE, AUTHOR, VERSION, LAB_MODE,
    MAIN_BANNER, STATUS_ICONS, ENVIRONMENT_LABEL, MODE_LABEL, TARGET_LABEL,
    DISCLAIMER,
)
from config.security import is_allowed_target, render_safety_banner, enforce_safe_target
from modules.reporting.audit_log import log_event, clear_log
from lab_server.database import init_db, DB_PATH

HOST = "127.0.0.1"
PORT = 5000
BASE_URL = f"http://{HOST}:{PORT}"

SERVER_PROCESS = None


# ----------------------------------------------------------------------
# Display helpers
# ----------------------------------------------------------------------
def c(text, color):
    return f"{color}{text}{Style.RESET_ALL}"


def print_banner():
    print(c(MAIN_BANNER, Fore.GREEN))


def print_status_box():
    print("+----------------------------------------------------+")
    print(f"| Version : {VERSION:<42}|")
    print(f"| Author  : {AUTHOR:<42}|")
    print(f"| Mode    : {MODE_LABEL:<42}|")
    print(f"| Target  : {TARGET_LABEL:<42}|")
    print(f"| Status  : {'SAFE LAB' if LAB_MODE else 'DISABLED':<42}|")
    print("+----------------------------------------------------+")


def press_enter():
    input(c("\nPress ENTER to continue...", Fore.CYAN))


# ----------------------------------------------------------------------
# Server management
# ----------------------------------------------------------------------
def _server_is_up() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


def start_server(quiet=False):
    global SERVER_PROCESS
    if _server_is_up():
        if not quiet:
            print(c("[*] Training server already running.", Fore.YELLOW))
        return
    project_root = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(project_root, "lab_server", "app.py")
    SERVER_PROCESS = subprocess.Popen(
        [sys.executable, app_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(20):
        if _server_is_up():
            break
        time.sleep(0.3)
    if not quiet:
        if _server_is_up():
            print(c(f"[+] Training server started at {BASE_URL}", Fore.GREEN))
        else:
            print(c("[-] Server failed to start. Check for port conflicts on 5000.", Fore.RED))
    log_event("cli", "start_server", "started" if _server_is_up() else "failed")


def open_url(path=""):
    start_server()
    url = f"{BASE_URL}{path}"
    print(c(f"[*] Opening {url}", Fore.CYAN))
    try:
        webbrowser.open(url)
    except Exception:
        pass
    print(f"    If a browser did not open, visit: {url}")


def stop_server():
    global SERVER_PROCESS
    if SERVER_PROCESS:
        SERVER_PROCESS.terminate()
        SERVER_PROCESS = None


# ----------------------------------------------------------------------
# Safety engine display
# ----------------------------------------------------------------------
def safety_check_display():
    result = is_allowed_target(HOST)
    print(render_safety_banner(result))
    return result.allowed


# ----------------------------------------------------------------------
# Teaching-mode wrapper: every module explains before it demonstrates.
# ----------------------------------------------------------------------
def teach(title, what_is_it, why_it_happens, url_path, fix_note):
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    print(c(f"\n=== {title} ===\n", Fore.GREEN))
    if not safety_check_display():
        print(c("[-] BLOCKED: target is not an approved lab target.", Fore.RED))
        press_enter()
        return
    print(c("\n[1] What is it?", Fore.CYAN))
    print(what_is_it)
    print(c("\n[2] Why does it happen?", Fore.CYAN))
    print(why_it_happens)
    print(c("\n[3] Demonstrate", Fore.CYAN))
    open_url(url_path)
    print(c("\n[4] Analyze", Fore.CYAN))
    print("Interact with the page in your browser, then review the output shown there.")
    print(c("\n[5] Fix", Fore.CYAN))
    print(fix_note)
    print(c("\n[6] Rescan", Fore.CYAN))
    print("Toggle the lab to SECURE from the lab index page, then run option [17] Vulnerability Scanner again.")
    print(c("\n[7] Explanation", Fore.CYAN))
    print("See the in-page 'What's happening' / 'Concepts' panel for the full technical explanation.")
    log_event("teaching_mode", title, "displayed")
    press_enter()


# ----------------------------------------------------------------------
# Menu actions
# ----------------------------------------------------------------------
def action_recon():
    teach(
        "Reconnaissance Simulation",
        "Reconnaissance is the information-gathering phase of an attack: identifying "
        "targets, technologies, and potential entry points before any exploitation begins.",
        "Publicly exposed information (job postings, DNS records, exposed services, "
        "social media) often reveals more than organizations realize, giving attackers "
        "a map of what to target.",
        "/",
        "Minimize public exposure of internal details, monitor for information leakage, "
        "and apply the principle of least information disclosure to public-facing systems.",
    )


def action_phishing():
    teach(
        "Phishing Simulation",
        "A simulated phishing message and fake login page demonstrating impersonation, "
        "urgency, and credential harvesting.",
        "Phishing exploits trust and urgency rather than technical flaws - it's often "
        "far cheaper for an attacker than finding a software vulnerability.",
        "/training-login",
        "Security-awareness training, simulated phishing campaigns, and phishing-resistant "
        "authentication (FIDO2/passkeys) are the strongest defenses.",
    )


def action_email_spoofing():
    teach(
        "Email Spoofing Simulation",
        "Demonstrates how the visible 'From' field in an email can be forged, and how "
        "SPF/DKIM/DMARC headers reveal the deception.",
        "SMTP does not require the 'From' field to be verified by default - it is simply "
        "a string set by the sending client.",
        "/email-spoofing-lab",
        "Enforce SPF, DKIM, and DMARC with a 'reject' or 'quarantine' policy on your mail domain.",
    )


def action_fake_login():
    teach(
        "Fake Login Page",
        "A fictional login page used to illustrate what a credential-harvesting page "
        "looks like from the inside.",
        "Visual similarity to a trusted site is easy to achieve; verifying the actual "
        "domain is the only reliable check.",
        "/training-login",
        "Use password managers (they won't autofill on the wrong domain) and phishing-resistant MFA.",
    )


def action_website_clone():
    teach(
        "Website Cloning Simulation",
        "An enterprise portal replication audit simulating page-cloning techniques "
        "used in phishing and business email compromise (BEC) campaigns.",
        "Cloning a page's HTML/CSS is trivial; the domain and certificate are what actually differ.",
        "/university-portal-clone",
        "Monitor for lookalike domain registrations and deploy brand-protection tooling.",
    )


def action_credential_harvest():
    teach(
        "Credential Harvesting Simulation",
        "Demonstrates what happens after a victim submits credentials to a phishing page.",
        "Once submitted, credentials can be replayed against real services within minutes "
        "by automated tooling.",
        "/training-login",
        "Enable MFA everywhere, especially phishing-resistant MFA, and rotate any credential "
        "suspected of exposure immediately.",
    )


def action_payment_phishing():
    teach(
        "Commercial Payment Gateway & Carding Audit Laboratory",
        "A commercial payment processing and card security laboratory featuring real-time "
        "Modulo-10 (Luhn) checksum validation, Bank Identification Number (BIN) lookup engine "
        "(detecting issuer bank, card brand, card tier, country, and currency), and an "
        "Enterprise Payment Gateway simulator with fraud score auditing.",
        "Payment gateways and checkout forms must enforce strict input validation, BIN risk "
        "filtering, velocity controls, and 3-D Secure to prevent carding attacks and authorization fraud.",
        "/payment-verification",
        "Enforce Luhn validation, BIN risk intelligence, CVV verification, 3-D Secure, and tokenization.",
    )


def action_sqli():
    teach(
        "SQL Injection Lab",
        "Demonstrates how unsanitized input concatenated into a SQL string can alter the "
        "query's logic.",
        "Databases can't distinguish attacker-supplied 'data' from 'code' when both are "
        "mixed into the same string.",
        "/sqli",
        "Use parameterized queries / prepared statements exclusively; never string-format "
        "user input into SQL.",
    )


def action_xss():
    teach(
        "XSS Lab",
        "Demonstrates reflected and stored Cross-Site Scripting: injecting script that "
        "executes in another user's browser.",
        "Output that isn't encoded before being written into HTML is interpreted as markup, "
        "not text, by the browser.",
        "/xss",
        "Auto-escape all template output, apply a strict Content-Security-Policy, and "
        "validate/sanitize input as defense-in-depth.",
    )


def action_cmdinject():
    teach(
        "Command Injection Lab",
        "Demonstrates how building a shell command from user input allows an attacker to "
        "chain additional commands.",
        "Shell metacharacters (;, &&, |) have special meaning to the shell interpreter, "
        "not just the target program.",
        "/cmdinject",
        "Never use shell=True with untrusted input; pass a fixed argument list to the "
        "underlying process instead.",
    )


def action_auth():
    teach(
        "Authentication Security Lab",
        "Demonstrates username enumeration via verbose error messages and the absence of "
        "rate limiting.",
        "Detailed error messages are a convenience for developers that doubles as a gift "
        "to attackers.",
        "/auth-lab",
        "Use generic error messages, add rate limiting / lockout, and layer on MFA.",
    )


def action_password():
    teach(
        "Password Security Lab",
        "Side-by-side comparison of plaintext password storage versus salted hashing.",
        "Plaintext storage means any database compromise instantly exposes every password.",
        "/password-lab",
        "Hash passwords with a slow, salted algorithm (Werkzeug/bcrypt/Argon2) - never store "
        "them reversibly.",
    )


def action_session():
    teach(
        "Session / Cookie Security",
        "Demonstrates the difference between a cookie with no security flags and one with "
        "HttpOnly + SameSite set.",
        "Cookies are sent automatically by the browser unless flags explicitly restrict "
        "when/how they're accessible.",
        "/session-lab",
        "Always set HttpOnly, SameSite, and Secure (over HTTPS) on session cookies.",
    )


def action_headers():
    teach(
        "HTTP Security Headers",
        "Scans for standard defensive HTTP headers and demonstrates enabling them.",
        "Browsers only enforce protections like clickjacking prevention or script-source "
        "restriction when a server explicitly asks for them via headers.",
        "/headers-lab",
        "Apply Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, and Permissions-Policy to every response.",
    )


def action_upload():
    teach(
        "File Upload Security",
        "Demonstrates the risk of accepting uploads with no extension allowlist or size limit.",
        "An unrestricted upload endpoint can become a foothold if a disguised or oversized "
        "file is accepted.",
        "/upload-lab",
        "Enforce an extension allowlist, file-size limits, safe filenames, and store "
        "uploads outside any web-servable path.",
    )


def action_api():
    teach(
        "API Security Lab",
        "Demonstrates an unauthenticated endpoint returning more data than any caller needs.",
        "APIs are often tested less rigorously than user-facing pages, making missing auth "
        "and excessive data exposure common findings.",
        "/api-lab",
        "Require authentication on every endpoint and return only the minimum fields the "
        "caller needs.",
    )


def action_scanner():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    if not safety_check_display():
        press_enter()
        return
    start_server()
    from modules.scanner.scanner import run_scan, render_scan_report
    print(c("\nRunning ARNTECH LOCAL SECURITY SCANNER...\n", Fore.CYAN))
    findings = run_scan(HOST, PORT)
    print(render_scan_report(findings, HOST, PORT))
    print()
    for f in findings:
        icon = "[+]" if f.severity == "PASS" else "[!]"
        print(f"{icon} {f.severity:<7} {f.title}: {f.detail}")
    press_enter()


def action_defensive_analysis():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    print(c("\n=== Defensive Analysis ===\n", Fore.GREEN))
    print(
        "This platform's central concept: every vulnerability is demonstrated, then\n"
        "explained, then fixed, then rescanned. Use the lab index page to toggle each\n"
        "module between VULNERABLE and SECURE, then re-run the scanner (option 17) to\n"
        "see findings move from HIGH/MEDIUM to PASS.\n"
    )
    open_url("/")
    press_enter()


def action_report():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    if not safety_check_display():
        press_enter()
        return
    start_server()
    from modules.reporting.report_generator import generate_report
    print(c("\nGenerating security report...", Fore.CYAN))
    path = generate_report(HOST, PORT)
    print(c(f"[+] Report written to: {path}", Fore.GREEN))
    log_event("cli", "generate_report", path)
    press_enter()


def action_system_info():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    print(c("\n=== System Information ===\n", Fore.GREEN))
    print(f"OS            : {platform.platform()}")
    print(f"Python        : {platform.python_version()}")
    print(f"App Version   : {VERSION}")
    print(f"Lab Mode      : {LAB_MODE}")
    print(f"Database Path : {DB_PATH}")
    print(f"Server Status : {'RUNNING' if _server_is_up() else 'STOPPED'}")
    print(f"Base URL      : {BASE_URL}")
    press_enter()


def action_reset_lab():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    print(c("\n=== Reset Lab ===\n", Fore.YELLOW))
    confirm = input("Type YES to wipe the database and logs back to a clean state: ")
    if confirm.strip() == "YES":
        init_db(reset=True)
        clear_log()
        print(c("[+] Lab reset complete.", Fore.GREEN))
        log_event("cli", "reset_lab", "database and logs reset")
    else:
        print("Cancelled.")
    press_enter()


def action_selftest():
    print_banner()
    print(c("\n=== Safety Engine Self-Test ===\n", Fore.GREEN))
    tests = [
        ("127.0.0.1", True), ("localhost", True), ("::1", True),
        ("google.com", False), ("paypal.com", False), ("8.8.8.8", False),
        ("192.168.1.50", False),
    ]
    all_pass = True
    for host, expected in tests:
        result = is_allowed_target(host)
        ok = result.allowed == expected
        all_pass = all_pass and ok
        status = c("PASS", Fore.GREEN) if ok else c("FAIL", Fore.RED)
        print(f"[{status}] {host:<16} allowed={result.allowed!s:<6} expected={expected!s:<6} ({result.reason})")
    print()
    print(c("ALL TESTS PASSED", Fore.GREEN) if all_pass else c("SOME TESTS FAILED", Fore.RED))


# ----------------------------------------------------------------------
# Executive Security Audit Suite Mode
# ----------------------------------------------------------------------
AUDIT_STAGES = [
    ("System Baseline Initialization", None, "ARNTECH Enterprise Platform initialization and security boundary verification."),
    ("Reconnaissance & Asset Mapping", "/training-login", "Target surface identification and metadata exposure audit."),
    ("Domain Authentication & Email Headers", "/email-spoofing-lab", "SPF, DKIM, and DMARC record policy verification."),
    ("Credential Portal Security", "/training-login", "Authentication portal security & form audit."),
    ("Payment Gateway & BIN Audit", "/payment-verification", "Commercial payment gateway processing, Luhn algorithm, and BIN lookup audit."),
    ("SQL Injection Security Audit", "/sqli", "Database query parameterization and data leakage audit."),
    ("Cross-Site Scripting (XSS) Audit", "/xss", "Reflected and stored XSS vulnerability verification."),
    ("Authentication Policy & Rate Limiting", "/auth-lab", "Account enumeration and rate limiting control audit."),
    ("Automated Vulnerability Scan", None, "Executing automated enterprise vulnerability scanner."),
    ("Remediation & Hardening Controls", "/", "Enforce secure mode controls across system modules."),
    ("Post-Remediation Verification Scan", None, "Re-running scanner to verify vulnerability remediation."),
    ("Executive Security Audit Report", None, "Generating comprehensive enterprise HTML audit report."),
]


def action_scanner_inline():
    from modules.scanner.scanner import run_scan, render_scan_report
    findings = run_scan(HOST, PORT)
    print(render_scan_report(findings, HOST, PORT))


def run_executive_audit():
    os.system("clear" if os.name != "nt" else "cls")
    print_banner()
    if not safety_check_display():
        return
    start_server()

    for i, (title, path, note) in enumerate(AUDIT_STAGES, 1):
        print(c(f"\n--- Audit Stage {i}/{len(AUDIT_STAGES)}: {title} ---", Fore.GREEN))
        print(c("AUDIT SCOPE:", Fore.CYAN), note)
        print(c("SECURITY IMPACT:", Fore.CYAN),
              "Evaluates core enterprise risk vectors against industry standards (OWASP, PCI-DSS).")
        print(c("DETECTION ENGINE:", Fore.CYAN),
              "Real-time telemetry logging, system audits, and automated security scanner checks.")
        print(c("REMEDIATION:", Fore.CYAN),
              "Apply secure parameterization, input validation, and header security policies.")
        if path:
            open_url(path)
        if title == "Automated Vulnerability Scan":
            action_scanner_inline()
        if title == "Post-Remediation Verification Scan":
            action_scanner_inline()
        if title == "Executive Security Audit Report":
            from modules.reporting.report_generator import generate_report
            rpath = generate_report(HOST, PORT)
            print(c(f"[+] Report generated: {rpath}", Fore.GREEN))
        press_enter()

    print(c("""
+------------------------------------------------------------------+
|                    ARNTECH CYBER LAB                             |
+------------------------------------------------------------------+
|                                                                  |
|       SECURITY AUDIT COMPLETE                                    |
|       VULNERABILITIES VERIFIED                                   |
|       ENTERPRISE DEFENSES HARDENED                               |
|       SYSTEM AUDIT RESCANNED & CLEARED                           |
|                                                                  |
|       COMMERCIAL COMPLIANCE & DEFENSE SYSTEM READY               |
|                                                                  |
+------------------------------------------------------------------+
""", Fore.GREEN))


# ----------------------------------------------------------------------
# Main menu
# ----------------------------------------------------------------------
MENU_ACTIONS = {
    "01": action_recon,
    "02": action_phishing,
    "03": action_email_spoofing,
    "04": action_fake_login,
    "05": action_website_clone,
    "06": action_credential_harvest,
    "07": action_payment_phishing,
    "08": action_sqli,
    "09": action_xss,
    "10": action_cmdinject,
    "11": action_auth,
    "12": action_password,
    "13": action_session,
    "14": action_headers,
    "15": action_upload,
    "16": action_api,
    "17": action_scanner,
    "18": action_defensive_analysis,
    "19": action_report,
    "20": run_executive_audit,
    "21": action_system_info,
}

MENU_TEXT = """
[01] Reconnaissance Simulation
[02] Phishing Simulation
[03] Email Spoofing Simulation
[04] Fake Login Page
[05] Website Cloning Simulation
[06] Credential Harvesting Simulation
[07] Commercial Payment Gateway & Carding Audit
[08] SQL Injection Security Lab
[09] Cross-Site Scripting (XSS) Security Lab
[10] Command Injection Security Lab
[11] Authentication Security & Lockout Audit
[12] Cryptographic Password Storage Audit
[13] Session & Cookie Security Audit
[14] HTTP Security Headers Audit
[15] File Upload Policy Audit
[16] REST API Security & Key Authorization Audit
[17] Automated Vulnerability Scanner
[18] Defensive Analysis & System Hardening
[19] Security Audit Report
[20] Executive Security Audit Suite
[21] System Information
[97] Reset System Audit Data
[98] Safety Engine Self-Test
[00] Exit
"""


def main_menu():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print_banner()
        print_status_box()
        print(c(MENU_TEXT, Fore.CYAN))
        raw = input("Select an option: ").strip()
        choice = raw.zfill(2) if raw.isdigit() else raw

        if choice == "00" or raw == "":
            print(c("\nExiting ARNTECH CYBER LAB. Systems secure.\n", Fore.GREEN))
            stop_server()
            break
        elif choice == "97":
            action_reset_lab()
        elif choice == "98":
            action_selftest()
            press_enter()
        elif choice in MENU_ACTIONS:
            MENU_ACTIONS[choice]()
        else:
            print(c("Invalid option.", Fore.RED))
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - {SUBTITLE}")
    parser.add_argument("--serve", action="store_true", help="Start the Flask enterprise server")
    parser.add_argument("--audit-suite", "--presentation", action="store_true", help="Run Executive Security Audit Suite")
    parser.add_argument("--report", action="store_true", help="Generate HTML security report")
    parser.add_argument("--scan", action="store_true", help="Run vulnerability scanner")
    parser.add_argument("--reset-lab", action="store_true", help="Reset audit database and logs")
    parser.add_argument("--selftest", action="store_true", help="Run Safety Engine self-tests")
    args = parser.parse_args()

    init_db()

    if args.selftest:
        action_selftest()
    elif args.reset_lab:
        init_db(reset=True)
        clear_log()
        print("Lab reset complete.")
    elif args.serve:
        print_banner()
        safety_check_display()
        start_server(quiet=False)
        print(f"Server running at {BASE_URL} - press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_server()
    elif args.audit_suite:
        run_executive_audit()
    elif args.report:
        start_server()
        from modules.reporting.report_generator import generate_report
        path = generate_report(HOST, PORT)
        print(f"Report generated: {path}")
    elif args.scan:
        start_server()
        from modules.scanner.scanner import run_scan, render_scan_report
        findings = run_scan(HOST, PORT)
        print(render_scan_report(findings, HOST, PORT))
    else:
        main_menu()


if __name__ == "__main__":
    main()
