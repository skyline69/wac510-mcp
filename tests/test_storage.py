from __future__ import annotations

import stat
from pathlib import Path

from wac510_mcp.config import Settings
from wac510_mcp.storage import EncryptedSettingsStore


async def test_settings_round_trip_encrypted_with_private_permissions(tmp_path: Path) -> None:
    store = EncryptedSettingsStore(tmp_path / "config")
    settings = Settings.from_values(
        url="https://192.0.2.1",
        username="admin",
        password="not-plaintext",
        timeout_seconds=12,
        download_directory=tmp_path / "downloads",
    )

    await store.save(settings)
    loaded = await store.load()

    assert loaded == settings
    encrypted = (store.directory / "settings.enc").read_bytes()
    assert b"not-plaintext" not in encrypted
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((store.directory / "settings.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((store.directory / "settings.enc").stat().st_mode) == 0o600


async def test_missing_settings_return_none(tmp_path: Path) -> None:
    store = EncryptedSettingsStore(tmp_path / "config")
    assert await store.load() is None

