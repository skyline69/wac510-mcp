"""Encrypted persistence for access-point settings."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import cast

from cryptography.fernet import Fernet, InvalidToken

from wac510_mcp.config import Settings
from wac510_mcp.errors import ConfigurationError


class EncryptedSettingsStore:
    """Store one AP configuration encrypted in a private local directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory.expanduser().resolve()
        self._key_path = self.directory / "settings.key"
        self._settings_path = self.directory / "settings.enc"
        self._lock = asyncio.Lock()

    async def load(self) -> Settings | None:
        async with self._lock:
            return await asyncio.to_thread(self._load_sync)

    async def save(self, settings: Settings) -> None:
        async with self._lock:
            await asyncio.to_thread(self._save_sync, settings)

    def _prepare_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)

    def _key(self) -> bytes:
        self._prepare_directory()
        try:
            return self._key_path.read_bytes()
        except FileNotFoundError:
            key = Fernet.generate_key()
            try:
                descriptor = os.open(
                    self._key_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                return self._key_path.read_bytes()
            with os.fdopen(descriptor, "wb") as output:
                output.write(key)
            return key

    def _load_sync(self) -> Settings | None:
        if not self._settings_path.exists():
            return None
        try:
            decrypted = Fernet(self._key()).decrypt(self._settings_path.read_bytes())
            raw = json.loads(decrypted)
        except (InvalidToken, OSError, ValueError, TypeError) as exc:
            raise ConfigurationError("saved WAC510 settings could not be read") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("saved WAC510 settings have an invalid format")
        data = cast(dict[str, object], raw)
        return Settings.from_values(
            url=str(data.get("url", "")),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            tls_verify=bool(data.get("tls_verify", False)),
            ca_bundle=str(data["ca_bundle"]) if data.get("ca_bundle") else None,
            timeout_seconds=str(data.get("timeout_seconds", "10")),
            download_directory=str(data.get("download_directory", ".")),
        )

    def _save_sync(self, settings: Settings) -> None:
        payload = json.dumps(
            {
                "url": settings.url,
                "username": settings.username,
                "password": settings.password,
                "tls_verify": settings.tls_verify,
                "ca_bundle": str(settings.ca_bundle) if settings.ca_bundle else None,
                "timeout_seconds": settings.timeout_seconds,
                "download_directory": str(settings.download_directory),
            },
            separators=(",", ":"),
        ).encode()
        encrypted = Fernet(self._key()).encrypt(payload)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=self.directory,
            prefix=".settings.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            output.write(encrypted)
        temporary.replace(self._settings_path)
        os.chmod(self._settings_path, 0o600)

