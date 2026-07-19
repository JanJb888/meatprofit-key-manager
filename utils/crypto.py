import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

FERNET_KEY = b"0MtGR5ssWObNMzk-z4PrVyBodw2kMPv_ffTmTQved44="
fernet = Fernet(FERNET_KEY)


def encrypt_license(data: bytes) -> bytes:
    """
    Шифрует данные лицензии
    """
    return fernet.encrypt(data)


def decrypt_license(token: bytes) -> bytes:
    """
    Расшифровывает данные лицензии
    """
    return fernet.decrypt(token)


def verify_signature(payload: dict, public_key_pem: bytes) -> bool:
    """
    Проверяет подпись в словаре лицензии.
    Ожидается, что payload содержит поле "signature" в hex формате.

    Возвращает True при успешной проверке, False при неверной подписи.
    """
    signature_hex = payload.get("signature")
    if not signature_hex:
        return False

    try:
        signature = bytes.fromhex(signature_hex)
    except Exception:
        return False

    # данные, которые подписывались — JSON без поля signature
    data_obj = {k: v for k, v in payload.items() if k != "signature"}
    data = json.dumps(data_obj, sort_keys=True).encode("utf-8")

    public_key = serialization.load_pem_public_key(public_key_pem)

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False