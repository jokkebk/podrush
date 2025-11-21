from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("podrush.env")
_env_loaded = False


def load_env_from_dotenv(path: Path = Path(".env")) -> None:
    """Load environment variables from a .env file once per process."""
    global _env_loaded
    if _env_loaded or not path.exists():
        _env_loaded = True
        return

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'").strip()
        if key and value and key not in os.environ:
            os.environ[key] = value
            logger.info("Loaded %s from .env", key)

    _env_loaded = True


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Expected integer for %s, got %r; using default %s", name, raw, default)
        return default
