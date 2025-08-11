import os
from datetime import datetime, timezone
from pathlib import Path

# Secure logging directory
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_audit.log"

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

def log_event(actor_email: str, action: str) -> None:
    """
    Logs user or admin actions securely with UTC timestamp.

    Args:
        actor_email (str): Email of the actor.
        action (str): Description of the action taken.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = f"[{timestamp}] {actor_email} - {action}\n"

    try:
        with LOG_FILE.open("a", encoding="utf-8") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        # Fail silently to avoid blocking flow (optional: notify dev/admin)
        print(f"[AUDIT_LOG_ERROR] Failed to write log: {e}")
