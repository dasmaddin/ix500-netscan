"""Configuration from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    host: str | None            # scanner IP; None = discover by broadcast
    password: str | None        # scanner password (factory default: last 4 digits of serial)
    iface: str | None           # local network interface; None = route toward scanner
    host_id: str                # "auto" = adopt the host ID the scanner advertises, or 12 hex digits
    output_dir: str
    filename_template: str
    blank_detection: bool
    blank_threshold: float      # share of "ink" pixels below which a page counts as blank
    file_mode: int
    state_dir: str
    api_bind: str
    api_port: int
    default_mode: str           # "local" or "cloud"
    log_level: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        e = os.environ if env is None else env
        mode = e.get("DEFAULT_MODE", "local").strip().lower()
        if mode not in ("local", "cloud"):
            raise ValueError("DEFAULT_MODE must be 'local' or 'cloud'")
        host_id = e.get("HOST_ID", "auto").strip().lower().replace(":", "").replace("-", "")
        if host_id != "auto" and (len(host_id) != 12 or any(c not in "0123456789abcdef" for c in host_id)):
            raise ValueError("HOST_ID must be 'auto' or 12 hex digits")
        return cls(
            host=e.get("IX500_HOST", "").strip() or None,
            password=e.get("IX500_PASSWORD", "") or None,
            iface=e.get("IX500_IFACE", "").strip() or None,
            host_id=host_id,
            output_dir=e.get("OUTPUT_DIR", "/output"),
            filename_template=e.get("FILENAME_TEMPLATE", "scan_%Y%m%d_%H%M%S.pdf"),
            blank_detection=_bool(e.get("BLANK_PAGE_DETECTION", "on")),
            blank_threshold=float(e.get("BLANK_PAGE_THRESHOLD", "0.0025")),
            file_mode=int(e.get("FILE_MODE", "0644"), 8),
            state_dir=e.get("STATE_DIR", "/state"),
            api_bind=e.get("API_BIND", "127.0.0.1"),
            api_port=int(e.get("API_PORT", "8099")),
            default_mode=mode,
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
        )
