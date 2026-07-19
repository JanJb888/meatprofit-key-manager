import sys
from pathlib import Path

from key_manager.key_manager import clone_key
from core.audit_logger import AuditLogger

# enforce license on start
from core.license_manager import LicenseManager

PRIVATE_KEY_FILE = Path("private_key.pem")


def main():
    # Проверяем лицензию ПЕРВЫМ
    LicenseManager.enforce()

    AuditLogger.init()

    print("MeatProfit Key Manager")
    print("1 — Копировать / восстановить ключ")

    try:
        choice = input("> ")
    except EOFError:
        return

    if choice == "1":
        try:
            source = Path(input("Путь к исходной флешке (например E:/): "))
            target = Path(input("Путь к новой флешке (например F:/): "))
        except EOFError:
            return

        try:
            private_key_pem = PRIVATE_KEY_FILE.read_bytes()
        except OSError as e:
            AuditLogger.log(f"Не удалось прочитать приватный ключ: {e}")
            print(f"ОШИБКА: не удалось прочитать {PRIVATE_KEY_FILE}: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            clone_key(source, target, private_key_pem)
        except Exception as e:
            AuditLogger.log(f"Ошибка копирования ключа: {e}")
            print(f"ОШИБКА при копировании ключа: {e}", file=sys.stderr)
            sys.exit(1)

        AuditLogger.log("Ключ успешно записан")
        print("Ключ успешно записан")


if __name__ == "__main__":
    main()