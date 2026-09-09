"""Lifecycle management for dynamically configured device clients."""

from __future__ import annotations

import asyncio

import httpx

from wac510_mcp.capabilities import CAPABILITIES
from wac510_mcp.client import WAC510Client
from wac510_mcp.config import Settings
from wac510_mcp.errors import ConfigurationError, ProtocolError
from wac510_mcp.storage import EncryptedSettingsStore


class DeviceRuntime:
    """Own the active AP client and replace it after OAuth setup."""

    def __init__(
        self,
        store: EncryptedSettingsStore,
        *,
        initial_settings: Settings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.store = store
        self._settings = initial_settings
        self._transport = transport
        self._client: WAC510Client | None = None
        self._lock = asyncio.Lock()

    async def settings(self) -> Settings | None:
        if self._settings is None:
            self._settings = await self.store.load()
        return self._settings

    def _active_client(self) -> WAC510Client | None:
        return self._client

    async def client(self) -> WAC510Client:
        active = self._active_client()
        if active is not None:
            return active
        async with self._lock:
            active = self._active_client()
            if active is not None:
                return active
            settings = await self.settings()
            if settings is None:
                raise ConfigurationError(
                    "The access point is not configured. Reconnect this MCP server to open setup."
                )
            self._client = WAC510Client(settings, transport=self._transport)
            return self._client

    async def configure(self, settings: Settings) -> None:
        """Validate, persist, and activate a submitted AP configuration."""

        async with WAC510Client(settings, transport=self._transport) as candidate:
            response = await candidate.query(CAPABILITIES["identity"].selector)
        system = response.get("system")
        monitor = system.get("monitor") if isinstance(system, dict) else None
        product = monitor.get("productId") if isinstance(monitor, dict) else None
        if product != "WAC510":
            raise ProtocolError(f"Expected a WAC510 but the device reported {product!r}")

        await self.store.save(settings)
        async with self._lock:
            previous = self._client
            self._settings = settings
            self._client = WAC510Client(settings, transport=self._transport)
        if previous is not None:
            await previous.aclose()

    async def aclose(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        if client is not None:
            await client.aclose()
