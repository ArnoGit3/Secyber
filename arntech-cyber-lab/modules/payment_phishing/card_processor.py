"""
ARNTECH ENTERPRISE CYBER LAB - Commercial Card Processor & Gateway Auditor
========================================================================
Implements real-time Luhn checksum validation, Bank Identification Number (BIN)
lookup engine, and Enterprise Gateway Transaction Processing & Security Audit.
"""

from __future__ import annotations
import re
import random
import time
from datetime import datetime


def luhn_checksum(card_number: str) -> bool:
    """Validate a card number using the Luhn algorithm (Mod 10)."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:
            checksum += digit
            
    return checksum % 10 == 0


BIN_DATABASE = {
    # Visa BINs
    "411111": {"bank": "JPMorgan Chase Bank, N.A.", "brand": "VISA", "type": "CREDIT", "level": "SIGNATURE", "country": "United States", "code": "US", "currency": "USD"},
    "400022": {"bank": "Barclays Bank UK PLC", "brand": "VISA", "type": "CREDIT", "level": "INFINITE", "country": "United Kingdom", "code": "GB", "currency": "GBP"},
    "424242": {"bank": "Stripe Gateway Test Bank", "brand": "VISA", "type": "CREDIT", "level": "CLASSIC", "country": "United States", "code": "US", "currency": "USD"},
    "450000": {"bank": "Equity Bank Kenya PLC", "brand": "VISA", "type": "DEBIT", "level": "GOLD", "country": "Kenya", "code": "KE", "currency": "KES"},
    "471600": {"bank": "Wells Fargo Bank, N.A.", "brand": "VISA", "type": "CREDIT", "level": "PLATINUM", "country": "United States", "code": "US", "currency": "USD"},
    "491600": {"bank": "Citibank, N.A.", "brand": "VISA", "type": "DEBIT", "level": "BUSINESS", "country": "United States", "code": "US", "currency": "USD"},

    # Mastercard BINs
    "510000": {"bank": "Bank of America, N.A.", "brand": "MASTERCARD", "type": "CREDIT", "level": "WORLD ELITE", "country": "United States", "code": "US", "currency": "USD"},
    "520000": {"bank": "HSBC Bank plc", "brand": "MASTERCARD", "type": "CREDIT", "level": "PLATINUM", "country": "United Kingdom", "code": "GB", "currency": "GBP"},
    "555555": {"bank": "Capital One Bank", "brand": "MASTERCARD", "type": "CREDIT", "level": "GOLD", "country": "United States", "code": "US", "currency": "USD"},
    "528000": {"bank": "KCB Bank Kenya Limited", "brand": "MASTERCARD", "type": "DEBIT", "level": "STANDARD", "country": "Kenya", "code": "KE", "currency": "KES"},
    "530000": {"bank": "Deutsche Bank AG", "brand": "MASTERCARD", "type": "CREDIT", "level": "CORPORATE", "country": "Germany", "code": "DE", "currency": "EUR"},

    # American Express BINs
    "371234": {"bank": "American Express National Bank", "brand": "AMEX", "type": "CREDIT", "level": "CENTURION", "country": "United States", "code": "US", "currency": "USD"},
    "378282": {"bank": "American Express National Bank", "brand": "AMEX", "type": "CREDIT", "level": "PLATINUM", "country": "United States", "code": "US", "currency": "USD"},
    "340000": {"bank": "American Express Australia Ltd", "brand": "AMEX", "type": "CREDIT", "level": "GOLD", "country": "Australia", "code": "AU", "currency": "AUD"},

    # Discover BINs
    "601100": {"bank": "Discover Bank", "brand": "DISCOVER", "type": "CREDIT", "level": "CASHBACK", "country": "United States", "code": "US", "currency": "USD"},
    "601102": {"bank": "Discover Bank", "brand": "DISCOVER", "type": "CREDIT", "level": "IT MILES", "country": "United States", "code": "US", "currency": "USD"},

    # JCB BINs
    "352800": {"bank": "JCB Co., Ltd.", "brand": "JCB", "type": "CREDIT", "level": "PREMIER", "country": "Japan", "code": "JP", "currency": "JPY"},

    # UnionPay BINs
    "621234": {"bank": "China Construction Bank", "brand": "UNIONPAY", "type": "DEBIT", "level": "DIAMOND", "country": "China", "code": "CN", "currency": "CNY"},

    # Diners Club BINs
    "360000": {"bank": "Diners Club International", "brand": "DINERS CLUB", "type": "CREDIT", "level": "CORPORATE", "country": "United States", "code": "US", "currency": "USD"},

    # Maestro BINs
    "501800": {"bank": "Standard Chartered Bank", "brand": "MAESTRO", "type": "DEBIT", "level": "STANDARD", "country": "United Kingdom", "code": "GB", "currency": "GBP"},
}


def lookup_bin(card_number: str) -> dict:
    """
    Extract BIN (first 6 to 8 digits) and perform bank identification lookup,
    card network classification, and Luhn integrity evaluation.
    """
    clean_number = re.sub(r"\D", "", card_number or "")
    bin_prefix_6 = clean_number[:6] if len(clean_number) >= 6 else clean_number
    bin_prefix_8 = clean_number[:8] if len(clean_number) >= 8 else clean_number

    # Check 8-digit BIN first, then 6-digit BIN
    bin_info = BIN_DATABASE.get(bin_prefix_8) or BIN_DATABASE.get(bin_prefix_6)

    is_luhn = luhn_checksum(clean_number) if len(clean_number) >= 13 else False

    # Dynamic detection fallback if not matched in hardcoded BIN database
    if not bin_info:
        brand = "UNKNOWN"
        if clean_number.startswith("4"):
            brand = "VISA"
        elif clean_number.startswith(("51", "52", "53", "54", "55")) or (clean_number.startswith("22") and len(clean_number) >= 4):
            brand = "MASTERCARD"
        elif clean_number.startswith(("34", "37")):
            brand = "AMEX"
        elif clean_number.startswith(("6011", "65", "644", "645", "646", "647", "648", "649")):
            brand = "DISCOVER"
        elif clean_number.startswith("35"):
            brand = "JCB"
        elif clean_number.startswith("62"):
            brand = "UNIONPAY"
        elif clean_number.startswith(("300", "305", "36", "38")):
            brand = "DINERS CLUB"
        elif clean_number.startswith(("50", "56", "57", "58", "67")):
            brand = "MAESTRO"

        bin_info = {
            "bank": "Generic Financial Institution",
            "brand": brand,
            "type": "CREDIT" if brand in ["AMEX", "DISCOVER"] else "DEBIT/CREDIT",
            "level": "STANDARD",
            "country": "International / Unassigned",
            "code": "INT",
            "currency": "USD"
        }

    return {
        "bin_prefix": bin_prefix_6,
        "raw_number_masked": "*" * (len(clean_number) - 4) + clean_number[-4:] if len(clean_number) >= 4 else clean_number,
        "card_brand": bin_info["brand"],
        "card_type": bin_info["type"],
        "card_level": bin_info["level"],
        "issuer_bank": bin_info["bank"],
        "country_name": bin_info["country"],
        "country_code": bin_info["code"],
        "currency": bin_info["currency"],
        "is_luhn_valid": is_luhn,
        "digit_count": len(clean_number),
        "cvv_required_length": 4 if bin_info["brand"] == "AMEX" else 3,
    }


def is_expiry_valid(expiry: str) -> bool:
    """Validate expiration date format MM/YY or MM/YYYY and check if not expired."""
    if not expiry or "/" not in expiry:
        return False
    parts = expiry.strip().split("/")
    if len(parts) != 2:
        return False
    try:
        month = int(parts[0])
        year_val = int(parts[1])
        if month < 1 or month > 12:
            return False
        
        # Format year
        if year_val < 100:
            year = 2000 + year_val
        else:
            year = year_val

        now = datetime.now()
        if year < now.year:
            return False
        if year == now.year and month < now.month:
            return False
        return True
    except ValueError:
        return False


def process_gateway_transaction(
    cardholder: str,
    card_number: str,
    expiry: str,
    cvv: str,
    amount: float = 1.00,
    currency: str = "USD"
) -> dict:
    """
    Process authorization request through the Simulated Enterprise Payment Gateway.
    Validates card format, Luhn algorithm, expiry, CVV, performs BIN lookup,
    and returns authorization details and security audit findings.
    """
    start_time = time.time()
    clean_card = re.sub(r"\D", "", card_number or "")
    clean_cvv = re.sub(r"\D", "", cvv or "")
    bin_meta = lookup_bin(clean_card)
    
    # 1. Card Length & Digit Check
    if not clean_card or len(clean_card) < 13 or len(clean_card) > 19:
        return {
            "status": "DECLINED",
            "response_code": "DECLINED_INVALID_CARD_NUMBER",
            "error_code": "4001",
            "message": "Card number failed standard digit length requirements (13-19 digits).",
            "auth_code": None,
            "transaction_id": f"TXN-ERR-{random.randint(100000, 999999)}",
            "risk_score": 95,
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "bin_details": bin_meta,
            "gateway_protocol": "ISO 8583 / Enterprise Gateway API v2.4"
        }

    # 2. Luhn Check
    if not bin_meta["is_luhn_valid"]:
        return {
            "status": "DECLINED",
            "response_code": "DECLINED_LUHN_CHECKSUM_FAILURE",
            "error_code": "4002",
            "message": "Card number failed Modulo-10 (Luhn Algorithm) checksum verification.",
            "auth_code": None,
            "transaction_id": f"TXN-ERR-{random.randint(100000, 999999)}",
            "risk_score": 99,
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "bin_details": bin_meta,
            "gateway_protocol": "ISO 8583 / Enterprise Gateway API v2.4"
        }

    # 3. Expiry Check
    if not is_expiry_valid(expiry):
        return {
            "status": "DECLINED",
            "response_code": "DECLINED_EXPIRED_CARD",
            "error_code": "4003",
            "message": "Card expiration date is invalid or past expiration.",
            "auth_code": None,
            "transaction_id": f"TXN-ERR-{random.randint(100000, 999999)}",
            "risk_score": 75,
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "bin_details": bin_meta,
            "gateway_protocol": "ISO 8583 / Enterprise Gateway API v2.4"
        }

    # 4. CVV Verification
    req_cvv_len = bin_meta["cvv_required_length"]
    if len(clean_cvv) != req_cvv_len:
        return {
            "status": "DECLINED",
            "response_code": "DECLINED_INVALID_CVV",
            "error_code": "4004",
            "message": f"CVV verification failed. Expected {req_cvv_len} digits for {bin_meta['card_brand']}.",
            "auth_code": None,
            "transaction_id": f"TXN-ERR-{random.randint(100000, 999999)}",
            "risk_score": 85,
            "latency_ms": round((time.time() - start_time) * 1000, 2),
            "bin_details": bin_meta,
            "gateway_protocol": "ISO 8583 / Enterprise Gateway API v2.4"
        }

    # 5. Gateway Response Triggers based on test card endings
    if clean_card.endswith("0002"):
        status, resp_code, err_code, msg, risk = "DECLINED", "DECLINED_INSUFFICIENT_FUNDS", "5001", "Declined by issuer: Insufficient funds.", 40
    elif clean_card.endswith("0003"):
        status, resp_code, err_code, msg, risk = "DECLINED", "DECLINED_SUSPECTED_FRAUD", "5002", "Gateway fraud detection engine flagged high velocity risk.", 92
    elif clean_card.endswith("0004"):
        status, resp_code, err_code, msg, risk = "DECLINED", "DECLINED_RESTRICTED_CARD", "5003", "Card is restricted or reported lost/stolen.", 98
    else:
        status, resp_code, err_code, msg, risk = "APPROVED", "AUTHORIZED_AND_CAPTURED", "1000", "Payment authorized successfully.", 12

    auth_code = f"AUTH-{random.randint(100000, 999999)}" if status == "APPROVED" else None
    txn_id = f"TXN-{random.randint(10000000, 99999999)}"

    latency = round(random.uniform(110, 280), 2)

    return {
        "status": status,
        "response_code": resp_code,
        "error_code": err_code,
        "message": msg,
        "auth_code": auth_code,
        "transaction_id": txn_id,
        "cardholder": cardholder,
        "amount": f"{amount:.2f}",
        "currency": currency or bin_meta["currency"],
        "risk_score": risk,
        "latency_ms": latency,
        "bin_details": bin_meta,
        "gateway_protocol": "ISO 8583 / Enterprise Gateway API v2.4",
        "processed_at": datetime.now().isoformat()
    }
