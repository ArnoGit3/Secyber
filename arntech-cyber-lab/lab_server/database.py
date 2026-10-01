"""
ARNTECH CYBER LAB - Enterprise Database Layer
============================================
A single SQLite database (data/lab.db) backing the commercial audit platform.
"""

from __future__ import annotations
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "lab.db")

os.makedirs(DB_DIR, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


SCHEMA = """
-- Commercial Vulnerable product catalog table
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    secret_note TEXT NOT NULL
);

-- Insecure authentication table
CREATE TABLE IF NOT EXISTS users_insecure (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_plaintext TEXT NOT NULL
);

-- Secure hashed authentication table
CREATE TABLE IF NOT EXISTS users_secure (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- System feedback and comment auditing table
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Credential security attempt table
CREATE TABLE IF NOT EXISTS credential_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_masked TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'CREDENTIAL SECURITY AUDIT',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Commercial Payment Gateway Audit & Transaction Log Table
CREATE TABLE IF NOT EXISTS payment_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cardholder TEXT NOT NULL,
    card_masked TEXT NOT NULL,
    bin_prefix TEXT,
    card_brand TEXT,
    card_type TEXT,
    card_level TEXT,
    issuer_bank TEXT,
    country TEXT,
    expiry TEXT NOT NULL,
    amount REAL DEFAULT 0.00,
    currency TEXT DEFAULT 'USD',
    luhn_valid INTEGER DEFAULT 1,
    gateway_status TEXT DEFAULT 'APPROVED',
    auth_code TEXT,
    risk_score INTEGER DEFAULT 0,
    classification TEXT NOT NULL DEFAULT 'COMMERCIAL GATEWAY AUDIT LOG',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Enterprise API Accounts Table
CREATE TABLE IF NOT EXISTS api_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    internal_notes TEXT NOT NULL,
    api_token TEXT NOT NULL
);

-- Login authentication auditing table
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    success INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db(reset: bool = False) -> None:
    """Create tables and seed system data. If reset=True, drop first."""
    conn = get_connection()
    cur = conn.cursor()

    if reset:
        for table in [
            "products", "users_insecure", "users_secure", "comments",
            "credential_attempts", "payment_attempts", "api_accounts",
            "login_attempts",
        ]:
            cur.execute(f"DROP TABLE IF EXISTS {table}")

    cur.executescript(SCHEMA)

    # Seed products
    cur.execute("SELECT COUNT(*) AS c FROM products")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO products (name, category, price, secret_note) VALUES (?, ?, ?, ?)",
            [
                ("Enterprise Firewall Appliance", "Hardware", 1299.99, "sys-key-FW9921"),
                ("ARNTECH Security Audit License", "Software", 499.99, "sys-key-SW1022"),
                ("HSM Cryptographic Key Card", "Hardware", 249.99, "sys-key-HSM441"),
                ("Enterprise Incident Response Suite", "Software", 899.00, "sys-key-IR7701"),
            ],
        )

    # Seed demo users
    cur.execute("SELECT COUNT(*) AS c FROM users_insecure")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO users_insecure (username, password_plaintext) VALUES (?, ?)",
            [
                ("audit_analyst", "SecuredPass2026!"),
                ("system_admin", "adminPass2026"),
            ],
        )

    cur.execute("SELECT COUNT(*) AS c FROM users_secure")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO users_secure (username, password_hash) VALUES (?, ?)",
            [
                ("audit_analyst", generate_password_hash("SecuredPass2026!")),
                ("system_admin", generate_password_hash("adminPass2026")),
            ],
        )

    # Seed initial comments
    cur.execute("SELECT COUNT(*) AS c FROM comments")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO comments (author, body) VALUES (?, ?)",
            [
                ("sec_auditor_1", "Vulnerability verification completed on endpoint."),
                ("sec_auditor_2", "Security headers enforce strict content policy."),
            ],
        )

    # Seed API accounts
    cur.execute("SELECT COUNT(*) AS c FROM api_accounts")
    if cur.fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO api_accounts (username, email, internal_notes, api_token) VALUES (?, ?, ?, ?)",
            [
                ("sys.auditor1", "auditor1@arntech-security.internal", "Enterprise API Tier 1", "tok_ent_alpha9981"),
                ("sys.auditor2", "auditor2@arntech-security.internal", "Enterprise API Tier 2", "tok_ent_beta8872"),
            ],
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("ARNTECH CYBER LAB database initialized at:", DB_PATH)
