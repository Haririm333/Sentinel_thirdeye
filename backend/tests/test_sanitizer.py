"""
Tests for Data Sanitizer and Sensitive Information Protection
Ensures passwords, tokens, full bank accounts, and credit card numbers are redacted.
"""

from fastapi import status
from sentinel.backend.app.services.sanitizer import sanitize_text, is_luhn_valid


def test_sanitize_credentials_and_tokens():
    """Verify password, token, and bearer strings are replaced."""
    text1, mod1 = sanitize_text("user=admin&password=SuperSecretPassword123!")
    assert mod1 is True
    assert "SuperSecretPassword123!" not in text1
    assert "password=[REDACTED_SECRET]" in text1

    text2, mod2 = sanitize_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsIn...")
    assert mod2 is True
    assert "Bearer [REDACTED_SECRET]" in text2


def test_bank_account_masking():
    """Verify bank account numbers have all but the last 4 digits masked."""
    # 12-digit bank account
    text, modified = sanitize_text("bank_account_987654321012")
    assert modified is True
    assert "987654321012" not in text
    assert "1012" in text  # Last 4 preserved


def test_credit_card_luhn_redaction():
    """Verify valid Luhn credit card numbers are detected and redacted."""
    # Standard Visa test card: 4532 0151 1283 0366
    valid_card = "4532015112830366"
    assert is_luhn_valid(valid_card) is True

    text, modified = sanitize_text(f"payment_card={valid_card}")
    assert modified is True
    assert valid_card not in text
    assert "REDACTED_CARD_ending_0366" in text


def test_event_submission_sanitizes_resource_and_approval(client, sample_valid_event):
    """
    Submitting an event containing an accidental bank account or password
    must result in sanitized values in the database.
    """
    event_id = "e0000000-0000-0000-0000-000000000006"
    payload = sample_valid_event.copy()
    payload["event_id"] = event_id
    payload["resource_id"] = "ACC-987654321098"
    payload["approval_reference"] = "AUTH-token=secretToken123456"

    res = client.post("/api/v1/events", json=payload)
    assert res.status_code == status.HTTP_201_CREATED

    get_res = client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == status.HTTP_200_OK
    data = get_res.json()
    
    # Raw bank account number must NOT be in resource_id
    assert "987654321098" not in data["resource_id"]
    assert "1098" in data["resource_id"]
    
    # Raw secret token must NOT be in approval_reference
    assert "secretToken123456" not in data["approval_reference"]
    assert "[REDACTED_SECRET]" in data["approval_reference"]
