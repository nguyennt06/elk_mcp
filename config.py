"""Configuration is owned by the local operator, never by a tool call."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigurationError(ValueError):
    pass


_INDEX_NAME = re.compile(r"^[A-Za-z0-9._*,-]+$")


def _check_url(value: str, name: str, *, allow_loopback_http: bool = False) -> str:
    parsed = urlparse(value)
    if (
        (parsed.scheme != "https" and not (
            allow_loopback_http and parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1"}
        ))
        or not parsed.hostname or parsed.path not in ("", "/")
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ConfigurationError(f"{name} phải là URL HTTPS gốc (Kibana cho phép HTTP loopback), không có path")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    elastic_url: str
    elastic_api_key: str
    ca_cert: str
    kibana_url: str | None = None
    kibana_api_key: str | None = None
    event_index: str = "elk-lab-victim-ecs-*"
    alert_alias: str = ".alerts-security.alerts-default"
    max_days: int = 7
    max_limit: int = 100
    timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> "Settings":
        elastic_url = os.getenv("ELASTIC_URL", "https://127.0.0.1:9200")
        key = os.getenv("ELASTIC_API_KEY", "").strip()
        ca_cert = os.getenv("ELASTIC_CA_CERT", "").strip()
        kibana_url = os.getenv("KIBANA_URL", "").strip() or None
        kibana_key = os.getenv("KIBANA_API_KEY", "").strip() or None
        event_index = os.getenv("ELASTIC_EVENT_INDEX", "elk-lab-victim-ecs-*").strip()
        alert_alias = os.getenv("ELASTIC_ALERT_ALIAS", ".alerts-security.alerts-default").strip()

        if not key or key.startswith("ApiKey ") or any(c.isspace() for c in key):
            raise ConfigurationError("ELASTIC_API_KEY thiếu hoặc sai định dạng")
        if not ca_cert or not Path(ca_cert).is_file():
            raise ConfigurationError("ELASTIC_CA_CERT phải trỏ đến CA certificate có thật")
        patterns = event_index.split(",")
        if (
            not _INDEX_NAME.fullmatch(event_index) or "/" in event_index
            or any(not pattern or pattern in ("*", "_all") or pattern.startswith(".") for pattern in patterns)
            or len(patterns) > 3 or len(set(patterns)) != len(patterns)
        ):
            raise ConfigurationError("ELASTIC_EVENT_INDEX phải gồm 1–3 pattern cụ thể, không dùng * toàn cục")
        if not _INDEX_NAME.fullmatch(alert_alias) or "*" in alert_alias or "," in alert_alias:
            raise ConfigurationError("ELASTIC_ALERT_ALIAS phải là một alias cố định")
        if kibana_key and (kibana_key.startswith("ApiKey ") or any(c.isspace() for c in kibana_key)):
            raise ConfigurationError("KIBANA_API_KEY sai định dạng")

        return cls(
            elastic_url=_check_url(elastic_url, "ELASTIC_URL"),
            elastic_api_key=key,
            ca_cert=ca_cert,
            kibana_url=_check_url(kibana_url, "KIBANA_URL", allow_loopback_http=True) if kibana_url else None,
            kibana_api_key=kibana_key,
            event_index=event_index,
            alert_alias=alert_alias,
        )
