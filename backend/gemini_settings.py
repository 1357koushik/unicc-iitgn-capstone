"""
Gemini settings (API key and model): where they come from.

An admin can set them in two places:
  1. the dashboard (System Config) - saved in the app's database, used at once,
     no restart and no file editing; this wins when set;
  2. GEMINI_API_KEY / GEMINI_MODEL in .env (or the real environment) - an edit to
     .env is also picked up at once (see backend.config.current_setting).

The key itself is never sent back to the browser or written to the audit log:
only its last 4 characters are shown, so an admin can tell which key is in use.
"""

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from backend.config import current_setting
from backend.models import SystemConfig
from llm.gateway.api.gemini_provider import DEFAULT_GEMINI_MODEL, clean_api_key, clean_model_name

KEY_SETTING = "gemini_api_key"
MODEL_SETTING = "gemini_model"


def _stored(db: Session, name: str) -> str:
    row = db.query(SystemConfig).filter(SystemConfig.key == name).first()
    return (row.value or "").strip() if row else ""


def store(db: Session, name: str, value: str) -> None:
    """Save a setting; an empty value removes it (the .env value is then used again)."""
    row = db.query(SystemConfig).filter(SystemConfig.key == name).first()
    if value:
        if row:
            row.value = value
        else:
            db.add(SystemConfig(key=name, value=value))
    elif row:
        db.delete(row)
    db.commit()


def key_hint(key: str) -> str:
    """'...abcd': enough to recognise a key, useless to someone who wants to use it."""
    return f"...{key[-4:]}" if len(key) >= 8 else "(set)"


def current(db: Session, key: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
    """
    The key and model in use now, and where each comes from ('dashboard', 'env' or None).

    key / model: values about to be saved in the dashboard (None = unchanged, "" = removed),
    to see what would be in use after saving them.
    """
    key = clean_api_key(_stored(db, KEY_SETTING) if key is None else key)
    key_source = "dashboard" if key else None
    if not key:
        key = clean_api_key(current_setting("GEMINI_API_KEY"))
        key_source = "env" if key else None

    model = clean_model_name(_stored(db, MODEL_SETTING) if model is None else model)
    model_source = "dashboard" if model else None
    if not model:
        model = clean_model_name(current_setting("GEMINI_MODEL"))
        model_source = "env" if model else "default"
    return {
        "api_key": key,
        "key_source": key_source,
        "model": model or DEFAULT_GEMINI_MODEL,
        "model_source": model_source,
    }


def public_view(db: Session) -> Dict[str, Any]:
    """What the dashboard may show: everything except the key itself."""
    settings = current(db)
    return {
        "key_set": bool(settings["api_key"]),
        "key_hint": key_hint(settings["api_key"]) if settings["api_key"] else None,
        "key_source": settings["key_source"],
        "model": settings["model"],
        "model_source": settings["model_source"],
        "default_model": DEFAULT_GEMINI_MODEL,
    }
