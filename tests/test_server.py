from __future__ import annotations

import httpx
from fastmcp.client import Client

from tests.fake_ap import FakeAP, fake_settings
from wac510_mcp.server import create_server

EXPECTED_TOOLS = {
    "list_capabilities",
    "list_endpoints",
    "device_info",
    "query_capabilities",
    "list_clients",
    "radio_status",
    "traffic_statistics",
    "raw_query",
    "apply_configuration",
    "raw_request",
    "download_file",
    "upload_file",
    "reboot",
    "factory_reset",
}


async def test_server_exposes_complete_tool_set() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == EXPECTED_TOOLS


async def test_query_capabilities_returns_every_requested_domain() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        result = await client.call_tool(
            "query_capabilities", {"names": ["identity", "radio_status"]}
        )
    assert result.data is not None
    assert isinstance(result.data, dict)
    capabilities = result.data["capabilities"]
    assert isinstance(capabilities, dict)
    assert set(capabilities) == {"identity", "radio_status"}
    assert fake_ap.authenticated_requests == 2


async def test_configuration_write_returns_preview_without_network_request() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        result = await client.call_tool(
            "apply_configuration",
            {"payload": {"system": {"basicSettings": {"apName": "lab"}}}},
        )
    assert isinstance(result.data, dict)
    assert result.data["performed"] is False
    assert fake_ap.login_count == 0


async def test_factory_reset_requires_exact_token() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        result = await client.call_tool("factory_reset", {"confirm": "true"})
    assert isinstance(result.data, dict)
    assert result.data["required_confirmation"] == "FACTORY_RESET"
    assert fake_ap.mutation_attempts == 0


async def test_confirmed_configuration_write_reaches_device_once() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        result = await client.call_tool(
            "apply_configuration",
            {
                "payload": {"system": {"basicSettings": {"apName": "lab"}}},
                "confirm": True,
            },
        )
    assert isinstance(result.data, dict)
    assert result.data["performed"] is True
    assert fake_ap.mutation_attempts == 1


async def test_raw_request_forces_confirmation_for_known_write_endpoint() -> None:
    fake_ap = FakeAP()
    server = create_server(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
    async with Client(server) as client:
        result = await client.call_tool(
            "raw_request",
            {"endpoint": "/reboot", "payload": {"reboot": 1}, "mutating": False},
        )
    assert isinstance(result.data, dict)
    assert result.data["required_confirmation"] == "REBOOT"
    assert fake_ap.login_count == 0
