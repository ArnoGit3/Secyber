"""
ARNTECH ENTERPRISE CYBER LAB - Commercial Security & Gateway Audit Server
========================================================================
Flask application powering the ARNTECH Enterprise Security Suite.
Operates within the secure lab environment against local targets.

Each security module features dynamic dual-state inspection:
  VULNERABLE (Default mode for security audit & flaw detection)
  SECURE     (Hardened defense implementation & active remediation)
"""

from __future__ import annotations
import os
import re
import shlex
import subprocess
import sys
import time
import uuid

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, jsonify, make_response
)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.branding import (
    APP_NAME, TAGLINE, FICTIONAL_BANK, FICTIONAL_UNIVERSITY,
    FICTIONAL_UNIVERSITY_DOMAIN,
)
from modules.reporting.audit_log import log_event
from modules.payment_phishing.card_processor import (
    lookup_bin, luhn_checksum, process_gateway_transaction
)
from lab_server.database import get_connection, init_db, DB_PATH

app = Flask(__name__)
app.secret_key = "arntech-enterprise-lab-key-secured-environment"

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# Central module security state - VULNERABLE (True) vs SECURE (False).
# ----------------------------------------------------------------------
LAB_STATE = {
    "sqli": True,
    "xss": True,
    "cmdinject": True,
    "auth": True,
    "session": True,
    "headers": True,
    "upload": True,
    "api": True,
    "password": True,
}

# Command Injection Safety Net
CMD_HARD_BLOCK = [
    "rm ", "rm-", "rmdir", "shutdown", "reboot", "mkfs", " dd ", "dd if",
    "format", ":(){", "chmod", "chown", "sudo", "passwd", "kill", "pkill",
    "> /dev", "curl ", "wget ", "nc ", "netcat", "ssh ", "scp ",
]

# File Upload Safety Net
DANGEROUS_EXTENSIONS = {
    ".exe", ".sh", ".bat", ".cmd", ".php", ".py", ".js", ".jar",
    ".msi", ".dll", ".vbs", ".ps1", ".apk", ".com", ".scr",
}
SAFE_UPLOAD_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf", ".txt", ".csv"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB


def mask_card(number: str) -> str:
    digits = re.sub(r"\D", "", number)
    if len(digits) < 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_password(pw: str) -> str:
    return "*" * len(pw)


@app.before_request
def _ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()


# ----------------------------------------------------------------------
# INDEX DASHBOARD
# ----------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", state=LAB_STATE, app_name=APP_NAME, tagline=TAGLINE)


@app.route("/toggle/<lab>")
def toggle_lab(lab):
    if lab in LAB_STATE:
        LAB_STATE[lab] = not LAB_STATE[lab]
        log_event("toggle", lab, "VULNERABLE" if LAB_STATE[lab] else "SECURE")
        flash(f"{lab.upper()} module is now {'VULNERABLE' if LAB_STATE[lab] else 'SECURE (Hardened)'}")
    return redirect(url_for("index"))


@app.route("/reset-lab-data")
def reset_lab_data():
    conn = get_connection()
    conn.execute("DELETE FROM credential_attempts")
    conn.execute("DELETE FROM payment_attempts")
    conn.execute("DELETE FROM login_attempts")
    conn.execute("DELETE FROM comments WHERE id > 2")
    conn.commit()
    conn.close()
    log_event("reset", "reset-lab-data", "cleared audit database tables")
    flash("System audit data reset to baseline configuration.")
    return redirect(url_for("index"))


# ----------------------------------------------------------------------
# CREDENTIAL SECURITY & AUTHENTICATION AUDIT
# ----------------------------------------------------------------------
@app.route("/training-login", methods=["GET", "POST"])
def training_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_connection()
        conn.execute(
            "INSERT INTO credential_attempts (username, password_masked) VALUES (?, ?)",
            (username, mask_password(password)),
        )
        conn.commit()
        conn.close()
        log_event("credential_security", "form_submit", f"username={username}")
        return render_template("credential_result.html", username=username,
                                domain=FICTIONAL_UNIVERSITY_DOMAIN)
    return render_template("training_login.html", university=FICTIONAL_UNIVERSITY,
                            domain=FICTIONAL_UNIVERSITY_DOMAIN)


# ----------------------------------------------------------------------
# COMMERCIAL PAYMENT GATEWAY AUDIT & CARDING VALIDATION LABORATORY
# ----------------------------------------------------------------------
@app.route("/api/bin-lookup", methods=["POST", "GET"])
def bin_lookup_api():
    """Live AJAX API Endpoint for BIN lookup & Luhn validation."""
    card_number = request.values.get("card_number", "")
    if not card_number and request.is_json:
        card_number = (request.get_json() or {}).get("card_number", "")
    bin_data = lookup_bin(card_number)
    return jsonify(bin_data)


@app.route("/payment-verification", methods=["GET", "POST"])
def payment_verification():
    if request.method == "POST":
        cardholder = request.form.get("cardholder", "John Doe")
        card_number = request.form.get("card_number", "")
        expiry = request.form.get("expiry", "")
        cvv = request.form.get("cvv", "")
        amount_raw = request.form.get("amount", "25.00")
        
        try:
            amount = float(amount_raw)
        except ValueError:
            amount = 25.00

        # Execute Payment Gateway Processing & Security Audit
        gw_result = process_gateway_transaction(
            cardholder=cardholder,
            card_number=card_number,
            expiry=expiry,
            cvv=cvv,
            amount=amount,
            currency="USD"
        )

        bin_info = gw_result["bin_details"]

        # Store complete audit log in SQLite database
        conn = get_connection()
        conn.execute(
            """INSERT INTO payment_attempts 
               (cardholder, card_masked, bin_prefix, card_brand, card_type, card_level, 
                issuer_bank, country, expiry, amount, currency, luhn_valid, gateway_status, 
                auth_code, risk_score) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cardholder,
                bin_info["raw_number_masked"],
                bin_info["bin_prefix"],
                bin_info["card_brand"],
                bin_info["card_type"],
                bin_info["card_level"],
                bin_info["issuer_bank"],
                bin_info["country_name"],
                expiry,
                amount,
                "USD",
                1 if bin_info["is_luhn_valid"] else 0,
                gw_result["status"],
                gw_result["auth_code"],
                gw_result["risk_score"]
            ),
        )
        conn.commit()
        conn.close()

        log_event("payment_gateway_audit", "transaction_processed", 
                  f"status={gw_result['status']} brand={bin_info['card_brand']} bank={bin_info['issuer_bank']}")

        return render_template(
            "payment_result.html",
            cardholder=cardholder,
            card_masked=bin_info["raw_number_masked"],
            bank=FICTIONAL_BANK,
            gw=gw_result,
            bin_info=bin_info
        )

    return render_template("payment_verification.html", bank=FICTIONAL_BANK)


# ----------------------------------------------------------------------
# SQL INJECTION AUDIT LAB
# ----------------------------------------------------------------------
@app.route("/sqli", methods=["GET", "POST"])
def sqli_lab():
    results = []
    query_shown = ""
    error = None
    search = request.form.get("q", "") if request.method == "POST" else ""

    if request.method == "POST":
        conn = get_connection()
        cur = conn.cursor()
        try:
            if LAB_STATE["sqli"]:
                # VULNERABLE: string interpolation
                query_shown = f"SELECT id, name, category, price FROM products WHERE name LIKE '%{search}%'"
                cur.execute(query_shown)
            else:
                # SECURE: parameterized query
                query_shown = "SELECT id, name, category, price FROM products WHERE name LIKE ?"
                cur.execute(query_shown, (f"%{search}%",))
            results = cur.fetchall()
        except Exception as e:
            error = str(e)
        finally:
            conn.close()
        log_event("sql_injection", f"search='{search}'",
                   "VULNERABLE query executed" if LAB_STATE["sqli"] else "parameterized query executed")

    return render_template("sqli.html", results=results, query_shown=query_shown,
                            search=search, error=error, vulnerable=LAB_STATE["sqli"])


# ----------------------------------------------------------------------
# XSS AUDIT LAB
# ----------------------------------------------------------------------
@app.route("/xss", methods=["GET", "POST"])
def xss_lab():
    reflected_input = request.args.get("msg", "")

    if request.method == "POST":
        author = request.form.get("author", "analyst")
        body = request.form.get("body", "")
        conn = get_connection()
        conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        conn.commit()
        conn.close()
        log_event("xss", "comment_post", f"author={author}")
        return redirect(url_for("xss_lab"))

    conn = get_connection()
    comments = conn.execute("SELECT author, body, created_at FROM comments ORDER BY id DESC").fetchall()
    conn.close()

    return render_template(
        "xss.html",
        reflected_input=reflected_input,
        comments=comments,
        vulnerable=LAB_STATE["xss"],
    )


# ----------------------------------------------------------------------
# COMMAND INJECTION AUDIT LAB
# ----------------------------------------------------------------------
@app.route("/cmdinject", methods=["GET", "POST"])
def cmdinject_lab():
    output = None
    command_shown = None
    blocked = False

    if request.method == "POST":
        host_input = request.form.get("host", "")

        lowered = host_input.lower()
        if any(bad in lowered for bad in CMD_HARD_BLOCK):
            blocked = True
            output = "[ARNTECH SAFETY NET] Dangerous command fragment blocked by security filter."
            log_event("command_injection", f"host='{host_input}'", "BLOCKED by hard safety net")
        elif LAB_STATE["cmdinject"]:
            command_shown = f'echo "Audit host status: {host_input}"'
            try:
                proc = subprocess.run(command_shown, shell=True, capture_output=True,
                                       text=True, timeout=3)
                output = proc.stdout + proc.stderr
            except Exception as e:
                output = str(e)
            log_event("command_injection", f"host='{host_input}'", "VULNERABLE shell command executed")
        else:
            allowlist = {"localhost-check": ["echo", "Host audit complete (SECURE: fixed argument array)"]}
            command_shown = "echo (fixed argument array - no shell interpretation)"
            proc = subprocess.run(allowlist["localhost-check"], capture_output=True, text=True, timeout=3)
            output = proc.stdout + proc.stderr
            log_event("command_injection", f"host='{host_input}'", "SECURE allowlisted command executed")

    return render_template("cmdinject.html", output=output, command_shown=command_shown,
                            blocked=blocked, vulnerable=LAB_STATE["cmdinject"])


# ----------------------------------------------------------------------
# AUTHENTICATION SECURITY LAB
# ----------------------------------------------------------------------
FAILED_ATTEMPTS = {}

@app.route("/auth-lab", methods=["GET", "POST"])
def auth_lab():
    message = None
    locked_out = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not LAB_STATE["auth"]:
            attempts = FAILED_ATTEMPTS.get(username, 0)
            if attempts >= 3:
                locked_out = True
                message = "Account temporarily locked due to security policy (3 failed attempts)."
                log_event("authentication", f"user={username}", "BLOCKED - rate limit / lockout")
                return render_template("auth_lab.html", message=message, locked_out=locked_out,
                                        vulnerable=False)

        conn = get_connection()
        row = conn.execute("SELECT password_hash FROM users_secure WHERE username=?", (username,)).fetchone()
        conn.close()

        success = bool(row) and check_password_hash(row["password_hash"], password)
        conn = get_connection()
        conn.execute("INSERT INTO login_attempts (username, success) VALUES (?, ?)",
                     (username, 1 if success else 0))
        conn.commit()
        conn.close()

        if LAB_STATE["auth"]:
            if not row:
                message = f"Authentication error: User account '{username}' not found."
            elif not success:
                message = "Authentication error: Invalid password."
            else:
                message = "Authentication successful."
            log_event("authentication", f"user={username}", message)
        else:
            if success:
                message = "Authentication successful."
                FAILED_ATTEMPTS[username] = 0
            else:
                FAILED_ATTEMPTS[username] = FAILED_ATTEMPTS.get(username, 0) + 1
                message = "Authentication failed: Invalid credentials provided."
            log_event("authentication", f"user={username}", message)

    return render_template("auth_lab.html", message=message, locked_out=locked_out,
                            vulnerable=LAB_STATE["auth"])


# ----------------------------------------------------------------------
# PASSWORD HASHING SECURITY LAB
# ----------------------------------------------------------------------
@app.route("/password-lab")
def password_lab():
    conn = get_connection()
    insecure = conn.execute("SELECT username, password_plaintext FROM users_insecure").fetchall()
    secure = conn.execute("SELECT username, password_hash FROM users_secure").fetchall()
    conn.close()
    return render_template("password_lab.html", insecure=insecure, secure=secure)


# ----------------------------------------------------------------------
# SESSION SECURITY LAB
# ----------------------------------------------------------------------
@app.route("/session-lab")
def session_lab():
    resp = make_response(render_template("session_lab.html", vulnerable=LAB_STATE["session"]))
    if LAB_STATE["session"]:
        resp.set_cookie("arntech_enterprise_session", str(uuid.uuid4()))
    else:
        resp.set_cookie("arntech_enterprise_session", str(uuid.uuid4()),
                         httponly=True, samesite="Lax")
    log_event("session_security", "cookie_set", "VULNERABLE" if LAB_STATE["session"] else "SECURE")
    return resp


# ----------------------------------------------------------------------
# HTTP SECURITY HEADERS LAB
# ----------------------------------------------------------------------
@app.after_request
def apply_security_headers(resp):
    if not LAB_STATE["headers"]:
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


@app.route("/headers-lab")
def headers_lab():
    return render_template("headers_lab.html", vulnerable=LAB_STATE["headers"])


# ----------------------------------------------------------------------
# FILE UPLOAD SECURITY AUDIT LAB
# ----------------------------------------------------------------------
@app.route("/upload-lab", methods=["GET", "POST"])
def upload_lab():
    message = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            message = "No file selected."
        else:
            filename = secure_filename(f.filename)
            ext = os.path.splitext(filename)[1].lower()

            if ext in DANGEROUS_EXTENSIONS:
                message = f"[ARNTECH SAFETY NET] File extension '{ext}' blocked by execution policy."
                log_event("file_upload", filename, "BLOCKED - dangerous extension")
            elif LAB_STATE["upload"]:
                path = os.path.join(UPLOAD_DIR, filename)
                f.save(path)
                message = f"File '{filename}' accepted without content filter validation."
                log_event("file_upload", filename, "VULNERABLE upload accepted")
            else:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                if ext not in SAFE_UPLOAD_EXTENSIONS:
                    message = f"Rejected: File extension '{ext}' not in security allowlist."
                elif size > MAX_UPLOAD_BYTES:
                    message = "Rejected: File exceeds maximum size quota (2MB)."
                else:
                    path = os.path.join(UPLOAD_DIR, filename)
                    f.save(path)
                    message = f"File '{filename}' validated against security policy and stored safely."
                log_event("file_upload", filename, message)

    return render_template("upload_lab.html", message=message, vulnerable=LAB_STATE["upload"])


# ----------------------------------------------------------------------
# API SECURITY AUDIT LAB
# ----------------------------------------------------------------------
@app.route("/api/accounts")
def api_accounts():
    conn = get_connection()
    rows = conn.execute("SELECT username, email, internal_notes, api_token FROM api_accounts").fetchall()
    conn.close()

    if LAB_STATE["api"]:
        log_event("api_security", "/api/accounts", "VULNERABLE - unauthenticated, sensitive payload exposed")
        return jsonify([dict(r) for r in rows])

    api_key = request.headers.get("X-ARNTECH-API-KEY")
    if api_key != "demo-enterprise-key":
        log_event("api_security", "/api/accounts", "SECURE - rejected unauthorized request")
        return jsonify({"error": "Unauthorized. Valid X-ARNTECH-API-KEY header required."}), 401

    log_event("api_security", "/api/accounts", "SECURE - authenticated, minimal schema returned")
    return jsonify([{"username": r["username"]} for r in rows])


@app.route("/api-lab")
def api_lab_page():
    return render_template("api_lab.html", vulnerable=LAB_STATE["api"])


# ----------------------------------------------------------------------
# EMAIL SPOOFING & DOMAIN SECURITY AUDIT
# ----------------------------------------------------------------------
@app.route("/email-spoofing-lab")
def email_spoofing_lab():
    sample_headers = {
        "From": f"Security Operations <security@{FICTIONAL_UNIVERSITY_DOMAIN}>",
        "Reply-To": f"sec-ops@{FICTIONAL_UNIVERSITY_DOMAIN}.external-target.internal",
        "Return-Path": "<bounce@external-target.internal>",
        "Message-ID": "<audit-sys-001@arntech-security.internal>",
        "Received": "from external-target.internal by mail.arntech-security.internal",
        "Authentication-Results": "spf=fail dkim=none dmarc=fail",
    }
    return render_template("email_spoofing_lab.html", headers=sample_headers,
                            university=FICTIONAL_UNIVERSITY)


# ----------------------------------------------------------------------
# ENTERPRISE PORTAL CLONING SIMULATION
# ----------------------------------------------------------------------
@app.route("/university-portal-clone")
def university_portal_clone():
    return render_template("university_portal_clone.html", university=FICTIONAL_UNIVERSITY)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
