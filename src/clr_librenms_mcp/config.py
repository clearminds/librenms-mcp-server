"""Configuration for LibreNMS MCP Server."""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "librenms" / "credentials.json"


class Settings(BaseSettings):
    """Settings loaded from credentials file or environment variables.

    Priority order:
    1. ~/.config/librenms/credentials.json
    2. Environment variables (LIBRENMS_URL, LIBRENMS_TOKEN) - override
    """

    librenms_url: str = ""
    librenms_token: str = ""
    librenms_transport: str = "stdio"
    librenms_log_level: str = "INFO"

    model_config = {"env_prefix": ""}

    def load_credentials(self) -> dict[str, Any]:
        """Load credentials with config-file-first, env-override pattern.

        Returns:
            Dict with url and token populated from file or env vars.
        """
        creds: dict[str, Any] = {}

        # 1. FIRST: Load from environment variables (base/fallback)
        if self.librenms_url:
            creds["url"] = self.librenms_url
        if self.librenms_token:
            creds["token"] = self.librenms_token

        # 2. THEN: Override with credentials.json file (takes priority)
        if CREDS_PATH.exists():
            try:
                file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                if "url" in file_creds:
                    creds["url"] = file_creds["url"]
                if "token" in file_creds:
                    creds["token"] = file_creds["token"]

                logger.info(f"Loaded LibreNMS credentials from {CREDS_PATH}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load {CREDS_PATH}: {e}")

        if not (creds.get("url") and creds.get("token")):
            logger.warning(
                "No LibreNMS credentials configured. Set LIBRENMS_URL/LIBRENMS_TOKEN "
                f"env vars or create {CREDS_PATH}"
            )

        return creds
