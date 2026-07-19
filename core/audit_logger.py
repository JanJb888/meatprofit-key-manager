import datetime
from pathlib import Path

STORAGE_DIR = Path("storage")
AUDIT_LOG_FILE = STORAGE_DIR / "audit.log"


class AuditLogger:
    """
    Простой аудит-логгер операций с лицензией/ключами.
    Пишет события в storage/audit.log с временной меткой (UTC).
    """

    @staticmethod
    def init() -> None:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def log(message: str) -> None:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{timestamp} {message}\n")
