"""Best-effort redaction of secrets from evidence strings.

Redaction is heuristic and not guaranteed. Do not rely on this to make
output safe for public sharing — always review before distributing reports.
"""

from __future__ import annotations

import re

# Patterns ordered from most- to least-specific so that the first match wins
# for overlapping patterns.
_REDACTION_RULES: list[tuple[str, str]] = [
    # Database URLs with credentials  postgres://user:pass@host
    (
        r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlite)"
        r"://[^:/@\s]+:)[^\s@\"'`]+(@[^\s\"'`]+)",
        r"\1[REDACTED]\2",
    ),
    # Authorization header values  Authorization: Bearer <token>
    (
        r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token|api[_-]?key)?\s*)[^\s\"'`,\]}{)]{8,}",
        r"\1[REDACTED]",
    ),
    # Cookie header values
    (
        r"(?i)((?:set-)?cookie\s*[:=]\s*[^\s]*?(?:token|session|auth|key|secret)[^\s]*?\s*=\s*)[^\s;\"'`,]{6,}",
        r"\1[REDACTED]",
    ),
    # URL credentials  https://user:password@host
    (
        r"(https?://[^:/@\s]+:)[^@\s\"'`]+(@)",
        r"\1[REDACTED]\2",
    ),
    # Sensitive query-string aliases  ?api_key=VALUE  ?token=VALUE
    (
        r"(?i)([?&](?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?token"
        r"|auth[_-]?token|client[_-]?secret)=)[^\s&\"'`#]{4,}",
        r"\1[REDACTED]",
    ),
    # Quoted assignment patterns  KEY = "VALUE"  KEY: VALUE  "KEY": "VALUE"
    # Handles unquoted, single-quoted, and double-quoted values (incl. spaces).
    # Also handles JSON-style "key": "value" where the key's closing quote appears
    # before the separator.
    (
        r'(?i)((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token'
        r'|private[_-]?key|client[_-]?secret|password|passwd|db[_-]?pass(?:word)?'
        r'|jwt[_-]?secret|encryption[_-]?key|signing[_-]?key|webhook[_-]?secret'
        r'|stripe[_-]?(?:secret|key)|openai[_-]?(?:api[_-]?)?key'
        r'|anthropic[_-]?(?:api[_-]?)?key|sendgrid[_-]?(?:api[_-]?)?key'
        r'|twilio[_-]?(?:auth[_-]?)?token|aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key'
        r'|github[_-]?token|npm[_-]?token)\s*["\']?\s*[=:]\s*)'
        r'(?:["\'][^"\']{6,}["\']|[A-Za-z0-9+/=_\-\.]{8,}["\']?)',
        r"\1[REDACTED]",
    ),
    # Generic high-entropy-looking 40-char hex (git tokens, etc.)
    (
        r'\b([0-9a-f]{40})\b',
        "[HEX40-REDACTED]",
    ),
    # sk-... style keys  (OpenAI, Stripe, Anthropic, etc.)
    (
        r'\b(sk-[A-Za-z0-9\-_]{20,})\b',
        "sk-[REDACTED]",
    ),
    # ghp_ / ghs_ / github_ prefixed tokens
    (
        r'\b((?:ghp|ghs|gho|github_pat)_[A-Za-z0-9_]{10,})\b',
        "[GH-TOKEN-REDACTED]",
    ),
]

_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(p), r) for p, r in _REDACTION_RULES
]


def redact(text: str) -> str:
    """Return a copy of *text* with likely secrets replaced by placeholders."""
    for pattern, replacement in _COMPILED:
        text = pattern.sub(replacement, text)
    return text


def redact_lines(lines: list[str], max_lines: int = 5) -> str:
    """Redact a list of evidence lines and join them, capped at *max_lines*."""
    redacted = [redact(line.rstrip()) for line in lines[:max_lines]]
    if len(lines) > max_lines:
        redacted.append(f"… ({len(lines) - max_lines} more lines omitted)")
    return "\n".join(redacted)
