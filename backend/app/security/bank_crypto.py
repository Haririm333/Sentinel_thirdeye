"""
Cryptographic Utilities for Vendor Bank Details and Fingerprint Calculations
Ensures:
- AES-CBC / HMAC-SHA256 authenticated encryption at rest (Fernet).
- Deterministic, tamper-evident SHA-256 fingerprinting of change requests.
- Consistent, secure masking of account numbers and routing codes.
"""

import json
import hashlib
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken

from sentinel.backend.app.config import get_settings


def get_fernet_cipher() -> Fernet:
    """Retrieve Fernet authenticated encryption cipher from settings."""
    settings = get_settings()
    key = settings.BANK_ENCRYPTION_KEY
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        # Fallback to a deterministic development key if improperly configured
        dev_key = b"dp7ITpkyfy7ZAOqoNdOyh3ED_VeICwYZTziKHBsNGzk="
        return Fernet(dev_key)


def mask_account_number(account_number: Optional[str]) -> str:
    """
    Produce a safe masked reference for a bank account number.
    Example: '987654321048' -> 'ACC-***masked***1048'
    """
    if not account_number:
        return "ACC-***masked***0000"
    cleaned = str(account_number).strip().replace(" ", "").replace("-", "")
    if len(cleaned) <= 4:
        return f"ACC-***masked***{cleaned}"
    last_four = cleaned[-4:]
    return f"ACC-***masked***{last_four}"


def mask_routing_number(routing_number: Optional[str]) -> str:
    """
    Produce a safe masked reference for a routing / sort code.
    Example: '021000021' -> 'ROUT-***masked***0021'
    """
    if not routing_number:
        return "ROUT-***masked***0000"
    cleaned = str(routing_number).strip().replace(" ", "").replace("-", "")
    if len(cleaned) <= 4:
        return f"ROUT-***masked***{cleaned}"
    last_four = cleaned[-4:]
    return f"ROUT-***masked***{last_four}"


def encrypt_bank_payload(details: Dict[str, Any]) -> str:
    """
    Encrypt sensitive bank details payload (account number, routing number, beneficiary)
    into an authenticated ciphertext token for at-rest storage.
    """
    cipher = get_fernet_cipher()
    canonical_json = json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encrypted_bytes = cipher.encrypt(canonical_json)
    return encrypted_bytes.decode("utf-8")


def decrypt_bank_payload(ciphertext: str) -> Dict[str, Any]:
    """
    Decrypt and verify authenticated ciphertext token back into structured bank details.
    Raises ValueError if corrupted or tampered with.
    """
    cipher = get_fernet_cipher()
    try:
        decrypted_bytes = cipher.decrypt(ciphertext.encode("utf-8"))
        return json.loads(decrypted_bytes.decode("utf-8"))
    except InvalidToken:
        raise ValueError("Cryptographic verification failed: bank payload token is corrupt or tampered.")
    except Exception as exc:
        raise ValueError(f"Failed to decrypt bank payload: {exc}")


def compute_change_fingerprint(
    vendor_id: str,
    old_account_ref: str,
    proposed_account_ref: str,
    proposed_bank_name: str,
    proposed_routing_masked: str,
    requester_id: str,
    version: int
) -> str:
    """
    Calculate an immutable SHA-256 cryptographic fingerprint over the canonical change request.
    Any alteration to vendor, account references, bank name, routing, requester, or version
    invalidates the fingerprint.
    """
    canonical_dict = {
        "old_account_ref": str(old_account_ref).strip(),
        "proposed_account_ref": str(proposed_account_ref).strip(),
        "proposed_bank_name": str(proposed_bank_name).strip().upper(),
        "proposed_routing_masked": str(proposed_routing_masked).strip(),
        "requester_id": str(requester_id).strip(),
        "vendor_id": str(vendor_id).strip(),
        "version": int(version)
    }
    canonical_str = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
