import time
import uuid
from typing import Dict, Any

# session_id -> {"created_at": float, "data": {...}}
SESSIONS: Dict[str, Dict[str, Any]] = {}

# Optional: expire sessions after X seconds (e.g., 30 minutes)
SESSION_TTL_SECONDS = 30 * 60


def create_session(data: Dict[str, Any]) -> str:
    session_id = uuid.uuid4().hex
    SESSIONS[session_id] = {"created_at": time.time(), "data": data}
    return session_id


def get_session(session_id: str) -> Dict[str, Any] | None:
    cleanup_expired_sessions()
    return SESSIONS.get(session_id)


def cleanup_expired_sessions() -> None:
    now = time.time()
    expired = [
        sid for sid, item in SESSIONS.items()
        if now - item["created_at"] > SESSION_TTL_SECONDS
    ]
    for sid in expired:
        SESSIONS.pop(sid, None)
