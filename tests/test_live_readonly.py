from __future__ import annotations

import os

import pytest

from wac510_mcp.capabilities import CAPABILITIES
from wac510_mcp.client import WAC510Client
from wac510_mcp.config import Settings


@pytest.mark.skipif(not os.getenv("WAC510_LIVE_TEST"), reason="requires live AP")
async def test_live_identity() -> None:
    async with WAC510Client(Settings.from_env()) as client:
        response = await client.query(CAPABILITIES["identity"].selector)
    system = response["system"]
    assert isinstance(system, dict)
    monitor = system["monitor"]
    assert isinstance(monitor, dict)
    assert monitor["productId"] == "WAC510"


@pytest.mark.skipif(not os.getenv("WAC510_LIVE_TEST"), reason="requires live AP")
async def test_live_named_capabilities() -> None:
    async with WAC510Client(Settings.from_env()) as client:
        for capability in CAPABILITIES.values():
            response = await client.query(capability.selector)
            assert response["status"] == 0
