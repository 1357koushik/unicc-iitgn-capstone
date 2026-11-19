"""
Settings (Team 4)

Every setting that can differ between computers - secret keys, AI model names,
addresses, security switches - is read from ENVIRONMENT VARIABLES, never written
in the code.

The easy way to set them is a file called `.env` in the project folder (copy
`.env.example` to `.env` and fill it in). This module loads that file when the app
starts. `.env` is listed in .gitignore, so secrets in it are never uploaded.
Variables that are already set in the environment win over the file.

The full list of settings, with explanations, is in `.env.example` and the README.
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


# Names whose value came from the .env file (not from the real environment).
# For these, current_setting() re-reads the file, so an edit takes effect without a restart.
_FROM_FILE: set = set()


def _dotenv_enabled(path: Path) -> bool:
    return os.environ.get("LOAD_DOTENV", "1") != "0" and path.is_file()


def _read_env_file(path: Path) -> dict:
    from dotenv import dotenv_values
    return {name: value for name, value in dotenv_values(path).items() if value is not None}


def load_env_file(path: Path = ENV_FILE) -> bool:
    """
    Load settings from a .env file if there is one. Returns True if a file was loaded.

    A real environment variable wins over the file - but only if it has a value. An
    EMPTY variable (for example "GEMINI_API_KEY=" passed in by Docker or set in a
    terminal) does not hide the value written in .env.
    """
    if not _dotenv_enabled(path):
        return False
    for name, value in _read_env_file(path).items():
        if os.environ.get(name, "").strip():
            continue                      # set in the real environment: that wins
        os.environ[name] = value
        _FROM_FILE.add(name)
    return True


def current_setting(name: str, default: str = "", path: Path = ENV_FILE) -> str:
    """
    A setting's value NOW, re-reading .env for settings that come from it.

    Used for settings an admin may change while the app runs (the Gemini API key and
    model), so that saving .env is enough - no restart. Settings given in the real
    environment (e.g. by Docker) still win and are not re-read.
    """
    if (name in _FROM_FILE or not os.environ.get(name, "").strip()) and _dotenv_enabled(path):
        value = _read_env_file(path).get(name)
        if value is not None:
            os.environ[name] = value
            _FROM_FILE.add(name)
        elif name in _FROM_FILE:
            os.environ.pop(name, None)    # the line was removed from .env
            _FROM_FILE.discard(name)
    return os.environ.get(name, "").strip() or default


def get_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip() or default


def get_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        raise RuntimeError(f"Setting {name} must be a whole number, got {value!r}.")


def get_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise RuntimeError(f"Setting {name} must be true or false, got {value!r}.")


# Load .env as soon as any part of the backend is imported (backend.database imports
# this module first), so every other module sees the settings.
load_env_file()
