import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_DIR = Path("storage")
AUDIT_FILE = AUDIT_DIR / "audit.log"


class AuditLogger:
    """Простой файловый аудит-логгер.

    Запись в лог намеренно не должна прерывать работу приложения, но и не
    должна проваливаться молча: при невозможности записать событие ошибка
    выводится в stderr, чтобы её было видно.
    """

    @staticmethod
    def init() -> None:
        """Готовит каталог для аудита. Ошибки создания каталога поднимаются,
        так как это явная инициализация."""
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def log(message: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        line = f"{timestamp} {message}\n"
        try:
            AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            with AUDIT_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as e:
            # Не прерываем работу из-за сбоя логирования, но делаем его видимым.
            print(f"AuditLogger: не удалось записать в аудит-лог: {e}", file=sys.stderr)
