from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from tests.fake_ap import FakeAP, fake_settings, make_client
from wac510_mcp.errors import AuthenticationError, DeviceConnectionError, ProtocolError
from wac510_mcp.models import JsonObject, redact

PRODUCT_QUERY: JsonObject = {"system": {"monitor": {"productId": ""}}}


async def test_query_logs_in_and_reuses_cookie_and_security_header() -> None:
    fake_ap = FakeAP()
    async with make_client(fake_ap) as client:
        result = await client.query(PRODUCT_QUERY)
        await client.query(PRODUCT_QUERY)
    assert result["system"] == {
        "monitor": {"productId": "WAC510", "sysVersion": "V9.9.6.8", "fwType": "Production"}
    }
    assert fake_ap.login_count == 1
    assert fake_ap.bootstrap_count == 1
    assert fake_ap.logout_count == 1
    assert fake_ap.authenticated_requests == 2
    assert "lhttpdsid=fake" in fake_ap.last_cookie


async def test_expired_query_reauthenticates_once() -> None:
    fake_ap = FakeAP()
    async with make_client(fake_ap) as client:
        await client.query(PRODUCT_QUERY)
        fake_ap.expire_next_request = True
        await client.query(PRODUCT_QUERY)
    assert fake_ap.login_count == 2
    assert fake_ap.authenticated_requests == 2


async def test_concurrent_initial_queries_share_one_login() -> None:
    fake_ap = FakeAP()
    async with make_client(fake_ap) as client:
        await asyncio.gather(client.query(PRODUCT_QUERY), client.query(PRODUCT_QUERY))
    assert fake_ap.login_count == 1
    assert fake_ap.authenticated_requests == 2


async def test_transport_failure_does_not_retry_mutation() -> None:
    fake_ap = FakeAP()
    fake_ap.fail_next_mutation = True
    async with make_client(fake_ap) as client:
        with pytest.raises(DeviceConnectionError, match="request"):
            await client.apply({"system": {"basicSettings": {"apName": "lab"}}})
    assert fake_ap.mutation_attempts == 1


async def test_bad_credentials_raise_authentication_error() -> None:
    fake_ap = FakeAP()
    settings = fake_settings()
    bad = settings.__class__(settings.url, "admin", "wrong")
    async with make_client(fake_ap).__class__(bad, transport=httpx.MockTransport(fake_ap.handler)) as client:
        with pytest.raises(AuthenticationError, match="Invalid username"):
            await client.query(PRODUCT_QUERY)


async def test_unknown_endpoint_is_rejected_before_network_access() -> None:
    fake_ap = FakeAP()
    async with make_client(fake_ap) as client:
        with pytest.raises(ProtocolError, match="not allowlisted"):
            await client.request("/not-real", {})
    assert fake_ap.login_count == 0


def test_redaction_hides_nested_secrets() -> None:
    assert redact({"password": "one", "system": {"sharedSecret": "two", "name": "visible"}}) == {
        "password": "[redacted]",
        "system": {"sharedSecret": "[redacted]", "name": "visible"},
    }


async def test_extra_headers_cannot_override_session_security() -> None:
    fake_ap = FakeAP()
    async with make_client(fake_ap) as client:
        with pytest.raises(ProtocolError, match="reserved headers"):
            await client.download(
                "/LogFile",
                {},
                client.settings.download_directory / "ignored",
                extra_headers={"Security": "attacker-controlled"},
            )


async def test_download_writes_authenticated_response(tmp_path: Path) -> None:
    fake_ap = FakeAP()
    destination = tmp_path / "document.json"
    async with make_client(fake_ap) as client:
        size = await client.download("/document", {"section": "help"}, destination)
    assert size == destination.stat().st_size
    assert b'"status":0' in destination.read_bytes()


async def test_upload_sends_multipart_file(tmp_path: Path) -> None:
    fake_ap = FakeAP()
    source = tmp_path / "firmware.tar"
    source.write_bytes(b"firmware")
    async with make_client(fake_ap) as client:
        response = await client.upload(
            "/file/firmwareupgrade",
            source,
            field_name="file",
            extra_headers={"check": "1"},
        )
    assert response["status"] == 0
    assert fake_ap.upload_count == 1


async def test_upload_reauthenticates_after_explicit_session_expiry(tmp_path: Path) -> None:
    fake_ap = FakeAP()
    source = tmp_path / "configuration.tar"
    source.write_bytes(b"configuration")
    async with make_client(fake_ap) as client:
        await client.query(PRODUCT_QUERY)
        fake_ap.expire_next_request = True
        response = await client.upload("/restoreSettings", source, field_name="file")
    assert response["status"] == 0
    assert fake_ap.login_count == 2
    assert fake_ap.upload_count == 1
