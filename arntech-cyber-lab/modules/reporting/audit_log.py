"""
ARNTECH CYBER LAB - Audit Logger
=================================
Every module action gets logged here: timestamp, module, action, result.

Sensitive-looking values (passwords, card numbers) are ALWAYS masked before
being written to disk, even though this is synthetic data - this models
good real-world logging hygiene as a teaching point in itself.
"""

from __future__ import annotations
import re
import os
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "logs")
LOG_FILE = os.path.join(LOG_DIR, "lab.log")

os.makedirs(LOG_DIR, exist_ok=True)

_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_CVV_KEY_RE = re.compile(r'("?cvv"?\s*[:=]\s*")([^"]+)(")', re.IGNORECASE)


def _mask(value: str) -> str:
    """Mask card-number-like and cvv-like substrings in a log line."""
    if not isinstance(value, str):
        value = str(value)
    value = _CARD_RE.sub(lambda m: "*" * (len(m.group(0)) - 4) + m.group(0)[-4:], value)
    value = _CVV_KEY_RE.sub(lambda m: m.group(1) + "***" + m.group(3), value)
    # mask anything explicitly tagged password=
    value = re.sub(r'("?password"?\s*[:=]\s*")([^"]+)(")', r"\1********\3", value, flags=re.IGNORECASE)
    return value


def log_event(module: str, action: str, result: str) -> None:
    """Append a masked, timestamped event line to data/logs/lab.log."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"[{ts}] module={module} action={_mask(action)} result={_mask(result)}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def read_recent(n: int = 50) -> list[str]:
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return lines[-n:]


def clear_log() -> None:
    open(LOG_FILE, "w").close()
