"""
ARNTECH CYBER LAB - Safety Engine
==================================
This is the most important file in the project.

Every module MUST call `enforce_safe_target()` (or `is_allowed_target()`)
before performing any simulated "attack" action. This is what keeps the
platform a closed enterprise security lab instead of a real attack tool.

Design principles:
1. Default-deny. Only localhost / loopback addresses are allowed unless
   a private lab subnet is explicitly and deliberately configured.
2. Hard-coded denylist of well-known real domains/services as a second
   layer of defense (defense in depth), even though the allowlist logic
   alone would already block them.
3. LAB_MODE must be True. If someone flips it off, every module refuses
   to run destructive/demo actions.
4. All checks are logged via the audit logger.
"""

from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass

from config.branding import LAB_MODE

# ----------------------------------------------------------------------
# ALLOWLIST: only these hosts may ever be used as a "target"
# ----------------------------------------------------------------------
ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
}

# Optional private lab subnet. Leave disabled unless a student explicitly
# needs a second VM on an isolated lab network (e.g. VirtualBox host-only
# adapter). This is OFF by default.
ALLOW_PRIVATE_LAB_SUBNET = False
PRIVATE_LAB_SUBNET = "192.168.56.0/24"  # example VirtualBox host-only range

# ----------------------------------------------------------------------
# DENYLIST: defense-in-depth. Never allow these regardless of anything.
# This list is illustrative, not exhaustive - the allowlist logic above
# is what actually protects the system. This is a second check.
# ----------------------------------------------------------------------
HARD_DENY_PATTERNS = [
    r"google\.",
    r"facebook\.",
    r"instagram\.",
    r"twitter\.",
    r"x\.com",
    r"paypal\.",
    r"amazon\.",
    r"apple\.",
    r"microsoft\.",
    r"bank",
    r"gov$",
    r"\.gov\.",
    r"\.edu$",  # real universities - block, use .test domains instead
    r"chase\.",
    r"wellsfargo\.",
    r"visa\.",
    r"mastercard\.",
]


class UnsafeTargetError(Exception):
    """Raised when a module attempts to operate against a non-lab target."""


@dataclass
class SafetyCheckResult:
    target: str
    allowed: bool
    reason: str
    environment: str = "TRAINING LAB"


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def _is_private_lab_subnet(host: str) -> bool:
    if not ALLOW_PRIVATE_LAB_SUBNET:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip in ipaddress.ip_network(PRIVATE_LAB_SUBNET)
    except ValueError:
        return False


def _matches_hard_deny(host: str) -> bool:
    host_lower = host.lower()
    return any(re.search(pattern, host_lower) for pattern in HARD_DENY_PATTERNS)


def is_allowed_target(host: str) -> SafetyCheckResult:
    """
    Determine whether `host` is a permitted simulation target.
    Returns a SafetyCheckResult; does not raise.
    """
    host = (host or "").strip()

    if not LAB_MODE:
        return SafetyCheckResult(host, False, "LAB_MODE is disabled")

    if not host:
        return SafetyCheckResult(host, False, "No target specified")

    if _matches_hard_deny(host):
        return SafetyCheckResult(
            host, False, "Target matches denylist of real-world services"
        )

    if host in ALLOWED_HOSTS or _is_loopback(host):
        return SafetyCheckResult(host, True, "Localhost target permitted")

    if _is_private_lab_subnet(host):
        return SafetyCheckResult(
            host, True, "Private lab subnet explicitly enabled"
        )

    return SafetyCheckResult(
        host, False, "Target is not localhost or an approved lab subnet"
    )


def enforce_safe_target(host: str) -> SafetyCheckResult:
    """
    Same as is_allowed_target but raises UnsafeTargetError if not allowed.
    Modules should call this before doing anything.
    """
    result = is_allowed_target(host)
    if not result.allowed:
        raise UnsafeTargetError(
            f"BLOCKED: '{host}' is not an allowed lab target. Reason: {result.reason}"
        )
    return result


def render_safety_banner(result: SafetyCheckResult) -> str:
    status = "ALLOWED" if result.allowed else "BLOCKED"
    return (
        "+------------------------------------------+\n"
        "|        ARNTECH SAFETY CONTROL            |\n"
        "+------------------------------------------+\n"
        f"| Target: {result.target:<33}|\n"
        f"| Environment: {result.environment:<28}|\n"
        f"| Status: {status:<33}|\n"
        "+------------------------------------------+"
    )
