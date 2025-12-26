import json
import sys
from pathlib import Path
from core.audit_logger import AuditLogger
from utils.crypto import decrypt_license, verify_signature

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
        AuditLogger.log("Проверка лицензии")

        usb = LicenseManager.find_usb_root()
        if not usb:
            AuditLogger.log("USB-ключ не найден")
            raise LicenseError("USB-ключ не найден")

        try:
            license_data = (usb / LICENSE_FILENAME).read_bytes()
            decrypted = decrypt_license(license_data)
            payload = json.loads(decrypted.decode("utf-8"))

            if not PUBLIC_KEY_FILE.exists():
                raise LicenseError("Файл public_key.pem не найден в приложении")

            public_key_pem = PUBLIC_KEY_FILE.read_bytes()

            # verify_signature ожидает payload с полем "signature"
            if not verify_signature(payload, public_key_pem):
                raise LicenseError("Неверная подпись лицензии")

            # проверка отпечатка (если есть в payload и на USB)
            if "fingerprint" in payload:
                fp_file = usb / FINGERPRINT_FILE
                if not fp_file.exists() or fp_file.read_text().strip() != str(payload["fingerprint"]):
                    raise LicenseError("Отпечаток USB не совпадает")

            AuditLogger.log("Лицензия подтверждена")

        except LicenseError:
            raise
        except Exception as e:
            AuditLogger.log(f"Ошибка лицензии: {e}")
            raise LicenseError(str(e))

    @staticmethod
    def enforce():
        """
        Вызывать ПЕРВЫМ при старте программы. При ошибке завершает процесс.
        """
        try:
            LicenseManager.validate()
        except LicenseError as e:
            AuditLogger.log(f"Ошибка лицензии: {e}")
            print(f"ОШИБКА ЛИЦЕНЗИИ: {e}")
            sys.exit(1)