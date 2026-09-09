from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.applications import Starlette

from tests.fake_ap import FakeAP
from wac510_mcp.oauth import WAC510OAuthProvider
from wac510_mcp.runtime import DeviceRuntime
from wac510_mcp.server import create_server
from wac510_mcp.storage import EncryptedSettingsStore


def oauth_client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="test-client",
        client_name="Test MCP Client",
        redirect_uris=[AnyUrl("http://127.0.0.1:9911/callback")],
        scope="wac510",
    )


def authorization_params() -> AuthorizationParams:
    return AuthorizationParams(
        state="state-value",
        scopes=["wac510"],
        code_challenge="challenge-value",
        redirect_uri=AnyUrl("http://127.0.0.1:9911/callback"),
        redirect_uri_provided_explicitly=True,
    )


async def test_setup_page_has_exact_title_and_never_renders_password(tmp_path: Path) -> None:
    fake_ap = FakeAP()
    runtime = DeviceRuntime(
        EncryptedSettingsStore(tmp_path / "config"),
        transport=httpx.MockTransport(fake_ap.handler),
    )
    provider = WAC510OAuthProvider(base_url="http://127.0.0.1:8000", runtime=runtime)
    client_info = oauth_client()
    await provider.register_client(client_info)
    setup_url = await provider.authorize(client_info, authorization_params())
    app = Starlette(routes=provider.get_routes("/mcp"))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        home = await client.get("/")
        assert home.status_code == 200
        assert "<title>WAC510 MCP</title>" in home.text

        response = await client.get(setup_url)
        assert response.status_code == 200
        assert "<title>WAC510 MCP</title>" in response.text
        assert "<h1>WAC510 MCP</h1>" in response.text
        assert "form-action" not in response.headers["content-security-policy"]

        request_id = parse_qs(urlsplit(setup_url).query)["request"][0]
        submitted = await client.post(
            "/setup",
            data={
                "request": request_id,
                "url": "https://192.0.2.1",
                "username": "admin",
                "password": "secret",
                "timeout_seconds": "10",
                "download_directory": str(tmp_path / "downloads"),
            },
            follow_redirects=False,
        )
        assert submitted.status_code == 303
        assert submitted.headers["location"].startswith("http://127.0.0.1:9911/callback?")

        second_url = await provider.authorize(client_info, authorization_params())
        second_page = await client.get(second_url)
        assert "Leave blank to keep the saved password." in second_page.text
        assert "secret" not in second_page.text
        assert "letter-spacing" not in second_page.text
        assert 'class="status"' not in second_page.text
        assert "Local access point control" not in second_page.text

        public_home = await client.get("/")
        assert "https://192.0.2.1" not in public_home.text
        assert "Leave blank to keep the saved password." not in public_home.text

    await runtime.aclose()


async def test_http_server_advertises_oauth_and_rejects_anonymous_mcp(tmp_path: Path) -> None:
    server = create_server(
        oauth_base_url="http://127.0.0.1:8000",
        config_directory=tmp_path / "config",
    )
    app = server.http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        metadata = await client.get("/.well-known/oauth-authorization-server")
        protected = await client.post("/mcp", json={})

    assert metadata.status_code == 200
    assert metadata.json()["authorization_endpoint"] == "http://127.0.0.1:8000/authorize"
    assert protected.status_code == 401


async def test_expired_authorization_has_actionable_page(tmp_path: Path) -> None:
    runtime = DeviceRuntime(EncryptedSettingsStore(tmp_path / "config"))
    provider = WAC510OAuthProvider(base_url="http://127.0.0.1:8000", runtime=runtime)
    app = Starlette(routes=provider.get_routes("/mcp"))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        response = await client.get("/setup?request=expired")

    assert response.status_code == 410
    assert "Authorization request expired." in response.text
    assert "start the MCP login again" in response.text
    assert '<div class="grid" hidden>' in response.text
    assert "<details hidden>" in response.text
    assert '<button type="submit" disabled hidden>' in response.text
    await runtime.aclose()


async def test_complete_oauth_code_flow_uses_setup_form(tmp_path: Path) -> None:
    fake_ap = FakeAP()
    runtime = DeviceRuntime(
        EncryptedSettingsStore(tmp_path / "config"),
        transport=httpx.MockTransport(fake_ap.handler),
    )
    provider = WAC510OAuthProvider(base_url="http://127.0.0.1:8000", runtime=runtime)
    app = Starlette(routes=provider.get_routes("/mcp"))
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    callback = "http://127.0.0.1:9911/callback"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        registration = await client.post(
            "/register",
            json={
                "client_name": "Test MCP Client",
                "redirect_uris": [callback],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "wac510",
            },
        )
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]

        authorization = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": callback,
                "scope": "wac510",
                "state": "test-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert authorization.status_code in {302, 303, 307}
        setup_url = authorization.headers["location"]
        request_id = parse_qs(urlsplit(setup_url).query)["request"][0]

        approval = await client.post(
            "/setup",
            data={
                "request": request_id,
                "url": "https://192.0.2.1",
                "username": "admin",
                "password": "secret",
                "timeout_seconds": "10",
                "download_directory": str(tmp_path / "downloads"),
            },
            follow_redirects=False,
        )
        assert approval.status_code == 303
        callback_query = parse_qs(urlsplit(approval.headers["location"]).query)
        assert callback_query["state"] == ["test-state"]

        token = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": callback_query["code"][0],
                "redirect_uri": callback,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200
        assert token.json()["token_type"] == "Bearer"
        assert token.json()["access_token"]

    await runtime.aclose()
