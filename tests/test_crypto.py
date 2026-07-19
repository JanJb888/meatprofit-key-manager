import json

import pytest
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from utils.crypto import decrypt_license, encrypt_license, verify_signature


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def sign_payload(payload: dict, private_key) -> dict:
    data = json.dumps(
        {k: v for k, v in payload.items() if k != "signature"}, sort_keys=True
    ).encode("utf-8")
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    signed = dict(payload)
    signed["signature"] = signature.hex()
    return signed


# ---------------------------------------------------------------------------
# encrypt_license / decrypt_license
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    data = b"secret license payload"
    token = encrypt_license(data)
    assert token != data
    assert decrypt_license(token) == data


def test_encrypt_produces_fernet_token():
    token = encrypt_license(b"anything")
    # A valid Fernet token can be decrypted with the module's key.
    assert Fernet(b"0MtGR5ssWObNMzk-z4PrVyBodw2kMPv_ffTmTQved44=").decrypt(token) == b"anything"


def test_encrypt_is_non_deterministic():
    # Fernet embeds a random IV/timestamp, so two encryptions differ.
    assert encrypt_license(b"same") != encrypt_license(b"same")


def test_encrypt_empty_bytes_roundtrip():
    token = encrypt_license(b"")
    assert decrypt_license(token) == b""


def test_decrypt_invalid_token_raises():
    with pytest.raises(InvalidToken):
        decrypt_license(b"not-a-valid-token")


def test_decrypt_wrong_key_raises():
    other_token = Fernet(Fernet.generate_key()).encrypt(b"payload")
    with pytest.raises(InvalidToken):
        decrypt_license(other_token)


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


def test_verify_signature_valid():
    private_key, public_pem = generate_rsa_keypair()
    payload = {"product": "MeatProfit", "license_type": "FULL"}
    signed = sign_payload(payload, private_key)
    assert verify_signature(signed, public_pem) is True


def test_verify_signature_ignores_signature_field_in_signed_data():
    # The signature must cover the payload with the "signature" key removed.
    private_key, public_pem = generate_rsa_keypair()
    payload = {"a": 1, "b": "two", "nested": {"x": [1, 2, 3]}}
    signed = sign_payload(payload, private_key)
    assert verify_signature(signed, public_pem) is True


def test_verify_signature_missing_signature_field():
    _, public_pem = generate_rsa_keypair()
    assert verify_signature({"product": "MeatProfit"}, public_pem) is False


def test_verify_signature_empty_signature_value():
    _, public_pem = generate_rsa_keypair()
    assert verify_signature({"signature": ""}, public_pem) is False


def test_verify_signature_non_hex_signature():
    _, public_pem = generate_rsa_keypair()
    payload = {"product": "MeatProfit", "signature": "zzzz-not-hex"}
    assert verify_signature(payload, public_pem) is False


def test_verify_signature_tampered_payload():
    private_key, public_pem = generate_rsa_keypair()
    signed = sign_payload({"amount": 100}, private_key)
    signed["amount"] = 999  # tamper after signing
    assert verify_signature(signed, public_pem) is False


def test_verify_signature_wrong_public_key():
    private_key, _ = generate_rsa_keypair()
    _, other_public_pem = generate_rsa_keypair()
    signed = sign_payload({"product": "MeatProfit"}, private_key)
    assert verify_signature(signed, other_public_pem) is False


def test_verify_signature_valid_hex_but_wrong_length():
    _, public_pem = generate_rsa_keypair()
    # Decodes as hex fine, but is not a valid RSA signature length.
    payload = {"product": "MeatProfit", "signature": "abcd"}
    assert verify_signature(payload, public_pem) is False


def test_verify_signature_non_rsa_public_key():
    # An EC public key rejects RSA padding args, raising a non-InvalidSignature
    # error that is swallowed by the catch-all branch, returning False.
    private_key, _ = generate_rsa_keypair()
    signed = sign_payload({"product": "MeatProfit"}, private_key)
    ec_public_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert verify_signature(signed, ec_public_pem) is False


def test_verify_signature_malformed_public_key_raises():
    # load_pem_public_key runs before the try/except in verify_signature, so a
    # malformed PEM propagates as a ValueError rather than returning False.
    private_key, _ = generate_rsa_keypair()
    signed = sign_payload({"product": "MeatProfit"}, private_key)
    with pytest.raises(ValueError):
        verify_signature(signed, b"-----NOT A KEY-----")
