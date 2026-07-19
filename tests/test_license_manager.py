import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from utils.crypto import (
    encrypt_license,
    verify_signature,
    SignatureVerificationError,
)
from core.license_manager import LicenseManager, LicenseError, PUBLIC_KEY_FILE


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, private_pem, public_pem


def sign_payload_with_private(payload: dict, private_key) -> dict:
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    p = dict(payload)
    p["signature"] = signature.hex()
    return p


def test_validate_success(tmp_path, monkeypatch):
    private_key, private_pem, public_pem = generate_rsa_keypair()

    payload = {
        "product": "MeatProfit",
        "license_type": "FULL",
        "issued": "2025-03-01",
        "fingerprint": "TEST-FP-123",
    }

    signed = sign_payload_with_private(payload, private_key)

    usb_dir = tmp_path / "usb"
    usb_dir.mkdir()

    # write encrypted license
    token = encrypt_license(json.dumps(signed).encode("utf-8"))
    (usb_dir / ".meatprofit.lic").write_bytes(token)

    # write fingerprint
    (usb_dir / "fingerprint.txt").write_text(payload["fingerprint"], encoding="utf-8")

    # point LicenseManager to our usb
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: usb_dir))

    # point public key file to temp file
    pubfile = tmp_path / "public_key.pem"
    pubfile.write_bytes(public_pem)
    monkeypatch.setattr("core.license_manager.PUBLIC_KEY_FILE", pubfile)

    # should not raise
    LicenseManager.validate()


def test_validate_missing_usb(monkeypatch):
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: None))
    with pytest.raises(LicenseError):
        LicenseManager.validate()


def test_enforce_exits_on_failure(monkeypatch):
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: None))
    with pytest.raises(SystemExit):
        LicenseManager.enforce()


def test_verify_signature_missing_signature():
    _, _, public_pem = generate_rsa_keypair()
    assert verify_signature({"product": "MeatProfit"}, public_pem) is False


def test_verify_signature_bad_hex_is_invalid():
    _, _, public_pem = generate_rsa_keypair()
    payload = {"product": "MeatProfit", "signature": "not-hex!!"}
    assert verify_signature(payload, public_pem) is False


def test_verify_signature_malformed_public_key_raises():
    # Повреждённый ключ — это ошибка конфигурации, а не "неверная подпись":
    # раньше она молча возвращала False.
    payload = {"product": "MeatProfit", "signature": "00ff"}
    with pytest.raises(SignatureVerificationError):
        verify_signature(payload, b"not a real pem key")


def test_validate_undecryptable_license_propagates(tmp_path, monkeypatch):
    usb_dir = tmp_path / "usb"
    usb_dir.mkdir()
    (usb_dir / ".meatprofit.lic").write_bytes(b"not-a-valid-fernet-token")
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: usb_dir))

    with pytest.raises(LicenseError) as exc_info:
        LicenseManager.validate()
    # исходная причина сохранена через chaining
    assert exc_info.value.__cause__ is not None


def test_validate_corrupt_json_propagates(tmp_path, monkeypatch):
    usb_dir = tmp_path / "usb"
    usb_dir.mkdir()
    token = encrypt_license(b"{ this is not json")
    (usb_dir / ".meatprofit.lic").write_bytes(token)
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: usb_dir))

    with pytest.raises(LicenseError) as exc_info:
        LicenseManager.validate()
    assert exc_info.value.__cause__ is not None


def test_validate_bad_signature(tmp_path, monkeypatch):
    private_key, _, public_pem = generate_rsa_keypair()
    payload = {"product": "MeatProfit", "fingerprint": "FP"}
    signed = sign_payload_with_private(payload, private_key)
    signed["product"] = "Tampered"  # invalidate signature

    usb_dir = tmp_path / "usb"
    usb_dir.mkdir()
    token = encrypt_license(json.dumps(signed).encode("utf-8"))
    (usb_dir / ".meatprofit.lic").write_bytes(token)
    monkeypatch.setattr(LicenseManager, "find_usb_root", staticmethod(lambda: usb_dir))

    pubfile = tmp_path / "public_key.pem"
    pubfile.write_bytes(public_pem)
    monkeypatch.setattr("core.license_manager.PUBLIC_KEY_FILE", pubfile)

    with pytest.raises(LicenseError):
        LicenseManager.validate()