import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

FERNET_KEY_ENV = "MEATPROFIT_FERNET_KEY"

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """
    Ленивая инициализация Fernet из переменной окружения.
    Ключ НЕ хранится в исходном коде.
    """
    global _fernet
    if _fernet is None:
        key = os.environ.get(FERNET_KEY_ENV)
        if not key:
            raise RuntimeError(
                f"Ключ шифрования лицензии не настроен. "
                f"Задайте переменную окружения {FERNET_KEY_ENV} "
                f"с валидным ключом Fernet."
            )
        _fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
    return _fernet


def encrypt_license(data: bytes) -> bytes:
    """
    Шифрует данные лицензии
    """
    return _get_fernet().encrypt(data)


def decrypt_license(token: bytes) -> bytes:
    """
    Расшифровывает данные лицензии
    """
    return _get_fernet().decrypt(token)


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