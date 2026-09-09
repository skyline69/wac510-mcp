"""Environment-driven configuration."""

from __future__ import annotations

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from wac510_mcp.errors import ConfigurationError


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is required")
    return value


def _parse_bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated settings for one access point."""

    url: str
    username: str
    password: str = field(repr=False)
    tls_verify: bool = False
    ca_bundle: Path | None = None
    timeout_seconds: float = 10.0
    download_directory: Path = Path.cwd()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if environ is None else environ
        url = _required(source, "WAC510_URL").rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("WAC510_URL must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ConfigurationError("WAC510_URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ConfigurationError("WAC510_URL must not contain a query or fragment")

        try:
            timeout = float(source.get("WAC510_TIMEOUT_SECONDS", "10"))
        except ValueError as exc:
            raise ConfigurationError("WAC510_TIMEOUT_SECONDS must be a number") from exc
        if timeout <= 0:
            raise ConfigurationError("WAC510_TIMEOUT_SECONDS must be greater than zero")

        ca_text = source.get("WAC510_CA_BUNDLE", "").strip()
        ca_bundle = Path(ca_text).expanduser() if ca_text else None
        if ca_bundle is not None and not ca_bundle.is_file():
            raise ConfigurationError("WAC510_CA_BUNDLE must name a readable file")

        download_directory = Path(source.get("WAC510_DOWNLOAD_DIRECTORY", ".")).expanduser().resolve()
        return cls(
            url=url,
            username=_required(source, "WAC510_USERNAME"),
            password=_required(source, "WAC510_PASSWORD"),
            tls_verify=_parse_bool(source.get("WAC510_TLS_VERIFY", "false"), "WAC510_TLS_VERIFY"),
            ca_bundle=ca_bundle,
            timeout_seconds=timeout,
            download_directory=download_directory,
        )

    def httpx_verify(self) -> bool | ssl.SSLContext:
        if self.ca_bundle is not None:
            return ssl.create_default_context(cafile=str(self.ca_bundle))
        return self.tls_verify

