import json
import sys
from pathlib import Path

from cryptography.fernet import InvalidToken

from core.audit_logger import AuditLogger
from utils.crypto import (
    SignatureVerificationError,
    decrypt_license,
    verify_signature,
)

LICENSE_FILENAME = ".meatprofit.lic"
SIGNATURE_FILE = "signature.sig"
FINGERPRINT_FILE = "fingerprint.txt"
PUBLIC_KEY_FILE = Path("public_key.pem")


class LicenseError(Exception):
    pass


class LicenseManager:
    """
    Управление лицензией, поиск на USB и валидация подписи/отпечатка.
    """

    @staticmethod
    def find_usb_root() -> Path | None:
        """
        Поиск USB, содержащей файл лицензии.
        Проверяет буквы D:..Z:
        """
        for drive in range(ord("D"), ord("Z") + 1):
            path = Path(f"{chr(drive)}:/")
            if (path / LICENSE_FILENAME).exists():
                return path
        return None

    @staticmethod
    def validate():
        """Проверяет лицензию. Любая ошибка проверки логируется в аудит и
        поднимается как LicenseError с сохранением исходной причины."""
        AuditLogger.log("Проверка лицензии")
        try:
            LicenseManager._validate()
        except LicenseError as e:
            AuditLogger.log(f"Ошибка лицензии: {e}")
            raise
        AuditLogger.log("Лицензия подтверждена")

    @staticmethod
    def _validate():
        usb = LicenseManager.find_usb_root()
        if not usb:
            raise LicenseError("USB-ключ не найден")

        try:
            license_data = (usb / LICENSE_FILENAME).read_bytes()
        except OSError as e:
            raise LicenseError(f"Не удалось прочитать файл лицензии: {e}") from e

        try:
            decrypted = decrypt_license(license_data)
        except InvalidToken as e:
            raise LicenseError("Не удалось расшифровать лицензию") from e

        try:
            payload = json.loads(decrypted.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise LicenseError(f"Повреждённые данные лицензии: {e}") from e
        if not isinstance(payload, dict):
            raise LicenseError("Неверный формат лицензии")

        if not PUBLIC_KEY_FILE.exists():
            raise LicenseError("Файл public_key.pem не найден в приложении")

        try:
            public_key_pem = PUBLIC_KEY_FILE.read_bytes()
        except OSError as e:
            raise LicenseError(f"Не удалось прочитать public_key.pem: {e}") from e

        # verify_signature ожидает payload с полем "signature"
        try:
            signature_ok = verify_signature(payload, public_key_pem)
        except SignatureVerificationError as e:
            raise LicenseError(f"Не удалось проверить подпись: {e}") from e
        if not signature_ok:
            raise LicenseError("Неверная подпись лицензии")

        # проверка отпечатка (если есть в payload и на USB)
        if "fingerprint" in payload:
            fp_file = usb / FINGERPRINT_FILE
            if not fp_file.exists():
                raise LicenseError("Отпечаток USB не найден")
            try:
                fingerprint = fp_file.read_text().strip()
            except OSError as e:
                raise LicenseError(f"Не удалось прочитать отпечаток USB: {e}") from e
            if fingerprint != str(payload["fingerprint"]):
                raise LicenseError("Отпечаток USB не совпадает")

    @staticmethod
    def enforce():
        """
        Вызывать ПЕРВЫМ при старте программы. При ошибке завершает процесс.
        """
        try:
            LicenseManager.validate()
        except LicenseError as e:
            # validate() уже записал ошибку в аудит.
            print(f"ОШИБКА ЛИЦЕНЗИИ: {e}", file=sys.stderr)
            sys.exit(1)