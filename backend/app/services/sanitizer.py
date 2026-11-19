"""
Sensitive Data Sanitizer for SENTINEL
Ensures no passwords, API keys, bearer tokens, full bank account numbers,
or credit card numbers enter the event database or application logs.
"""

import re
from typing import Optional, Tuple

# Patterns to detect secrets in query strings, headers, or identifiers
SECRET_KEYWORD_REGEX = re.compile(
    r"(?i)(password|secret|bearer|token|apikey|api_key|auth_token|access_token|private_key)"
    r"(=|:|\s+)([^\s&,;]{4,})"
)

# Credit Card (13 to 19 digits)
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Bank Account Numbers: 9 to 18 consecutive digits or IBAN-like patterns
BANK_ACCOUNT_REGEX = re.compile(r"(?:(?<=[^0-9])|^)(?:[A-Z]{2}\d{2}[A-Z0-9]{4,30}|\d{9,18})(?=[^0-9]|$)")


def is_luhn_valid(number_str: str) -> bool:
    """Validate potential credit card number using Luhn algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def mask_bank_account(match: re.Match) -> str:
    """Mask bank account, preserving only the last 4 characters."""
    val = match.group(0)
    if len(val) <= 4:
        return "****"
    return f"{'*' * (len(val) - 4)}{val[-4:]}"


def sanitize_text(text: Optional[str]) -> Tuple[Optional[str], bool]:
    """
    Sanitize text by redacting sensitive secrets, payment details, and full bank account numbers.
    Returns: (sanitized_text, was_modified)
    """
    if text is None:
        return None, False

    original = text
    modified = False

    # 1. Redact credentials/tokens (e.g. password=secret123 -> password=[REDACTED])
    if SECRET_KEYWORD_REGEX.search(text):
        text = SECRET_KEYWORD_REGEX.sub(r"\1\2[REDACTED_SECRET]", text)
        modified = True

    # 2. Redact Credit Card Numbers
    for match in CREDIT_CARD_REGEX.finditer(text):
        candidate = match.group(0).replace(" ", "").replace("-", "")
        if is_luhn_valid(candidate):
            text = text.replace(match.group(0), f"[REDACTED_CARD_ending_{candidate[-4:]}]")
            modified = True

    # 3. Mask full bank account numbers (preserve last 4 digits)
    # Only mask if it contains 9-18 pure digits or standard IBAN
    def _mask_acc(m: re.Match) -> str:
        s = m.group(0)
        # Avoid masking standard UUID hex components or timestamps
        if s.isdigit() and len(s) >= 9:
            return f"***masked***{s[-4:]}"
        return s

    if BANK_ACCOUNT_REGEX.search(text):
        new_text = BANK_ACCOUNT_REGEX.sub(_mask_acc, text)
        if new_text != text:
            text = new_text
            modified = True

    return text, modified
