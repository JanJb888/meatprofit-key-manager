from key_manager.key_manager import clone_key
from core.audit_logger import AuditLogger
from pathlib import Path

# enforce license on start
from core.license_manager import LicenseManager


def main():
    # Проверяем лицензию ПЕРВЫМ
    LicenseManager.enforce()

    AuditLogger.init()

    print("MeatProfit Key Manager")
    print("1 — Копировать / восстановить ключ")

    choice = input("> ")

    if choice == "1":
        source = Path(input("Путь к исходной флешке (например E:/): "))
        target = Path(input("Путь к новой флешке (например F:/): "))

        private_key_pem = Path("private_key.pem").read_bytes()

        clone_key(source, target, private_key_pem)
        print("Ключ успешно записан")


if __name__ == "__main__":
    main()