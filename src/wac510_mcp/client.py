"""Asynchronous client for the WAC510 local management protocol."""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Self

import httpx

from wac510_mcp.config import Settings
from wac510_mcp.errors import AuthenticationError, DeviceConnectionError, ProtocolError
from wac510_mcp.models import APResponse, JsonObject

SOCKET_ENDPOINT = "/socketCommunication"

# Every route referenced by the V9.9.6.8 web application. Login remains private
# to this client so raw callers cannot corrupt session state.
ALLOWED_ENDPOINTS = frozenset(
    {
        SOCKET_ENDPOINT,
        "/APtype",
        "/HardFactory",
        "/LogFile",
        "/MACfileUpload",
        "/TC_queryStatus",
        "/TC_update",
        "/aplog",
        "/captivePortal",
        "/changeUserPassword",
        "/cloudStatus",
        "/collectiveAPI",
        "/ctsSignup",
        "/document",
        "/file/firmwareupgrade",
        "/forgotPassword",
        "/getInsightFlag",
        "/getLatestTC",
        "/getVersion",
        "/local_firmware",
        "/logout",
        "/reboot",
        "/restoreSettings",
        "/sessionCheck",
        "/swapfirmware",
        "/upgradeSFTP",
        "/userName",
        "/xagentlog",
    }
)


def _error_details(payload: JsonObject) -> tuple[str | None, str | None]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return None, None
    code = data.get("err_code")
    message = data.get("err_mesg")
    return (str(code) if code is not None else None, str(message) if message is not None else None)


class WAC510Client(AbstractAsyncContextManager["WAC510Client"]):
    """Persistent client for one access point."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._http = httpx.AsyncClient(
            base_url=settings.url,
            timeout=settings.timeout_seconds,
            verify=settings.httpx_verify(),
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json"},
        )
        self._security_token: str | None = None
        self._session_generation = 0
        self._auth_lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._security_token is not None:
            try:
                await self._http.post(
                    "/logout",
                    json={"admin": self.settings.username},
                    headers=self._authenticated_headers(),
                )
            except httpx.HTTPError:
                pass
            finally:
                self._security_token = None
        await self._http.aclose()

    @staticmethod
    def validate_endpoint(endpoint: str) -> str:
        normalized = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        if normalized not in ALLOWED_ENDPOINTS:
            valid = ", ".join(sorted(ALLOWED_ENDPOINTS))
            raise ProtocolError(f"endpoint {normalized!r} is not allowlisted; valid endpoints: {valid}")
        return normalized

    async def _login(self, expected_generation: int | None = None) -> None:
        async with self._auth_lock:
            if self._security_token is not None and (
                expected_generation is None or self._session_generation != expected_generation
            ):
                return

            try:
                bootstrap = await self._http.get("/")
                bootstrap.raise_for_status()
            except httpx.HTTPError as exc:
                raise DeviceConnectionError(f"could not open a login session with {self.settings.url}") from exc

            payload: JsonObject = {
                "system": {
                    "basicSettings": {
                        "adminName": self.settings.username,
                        "adminPasswd": self.settings.password,
                    }
                }
            }
            headers = {"time": datetime.now(UTC).astimezone().strftime("%a %b %d %Y %H:%M:%S GMT%z (%Z)")}
            try:
                response = await self._http.post(SOCKET_ENDPOINT, json=payload, headers=headers)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise DeviceConnectionError(f"could not authenticate with {self.settings.url}") from exc

            result = self._decode(response, SOCKET_ENDPOINT)
            if result.status != 0:
                code, message = _error_details(result.payload)
                suffix = f" ({code})" if code else ""
                detail = message or (
                    "maximum concurrent login sessions reached"
                    if result.status == 401
                    else "credentials were rejected"
                )
                raise AuthenticationError(f"WAC510 authentication failed{suffix}: {detail}")

            security_token = response.headers.get("security")
            if not security_token:
                raise AuthenticationError("WAC510 authentication response omitted the security header")
            self._security_token = security_token
            self._session_generation += 1

    async def _ensure_authenticated(self) -> None:
        if self._security_token is None:
            await self._login()

    def _authenticated_headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        if self._security_token is None:
            raise AuthenticationError("WAC510 session is unavailable")
        headers = {"security": self._security_token}
        if extra is not None:
            reserved = {name.lower() for name in extra} & {"authorization", "cookie", "host", "security"}
            if reserved:
                names = ", ".join(sorted(reserved))
                raise ProtocolError(f"extra headers must not override reserved headers: {names}")
            headers.update(extra)
        return headers

    @staticmethod
    def _decode(response: httpx.Response, endpoint: str) -> APResponse:
        try:
            value = response.json()
        except ValueError as exc:
            raise ProtocolError(f"{endpoint} returned malformed JSON") from exc
        return APResponse.from_json(value, endpoint)

    @staticmethod
    def _raise_device_status(result: APResponse, endpoint: str) -> None:
        code, message = _error_details(result.payload)
        suffix = f", error {code}" if code else ""
        detail = f": {message}" if message else ""
        raise ProtocolError(f"{endpoint} failed with AP status {result.status}{suffix}{detail}")

    async def _post_json_once(self, endpoint: str, payload: JsonObject) -> APResponse:
        try:
            response = await self._http.post(
                endpoint,
                json=payload,
                headers=self._authenticated_headers(),
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise DeviceConnectionError(f"WAC510 request to {endpoint} failed") from exc
        return self._decode(response, endpoint)

    async def request(
        self,
        endpoint: str,
        payload: JsonObject,
        *,
        mutating: bool = False,
    ) -> JsonObject:
        """Send JSON to an allowlisted route and validate the AP envelope."""

        del mutating  # Transport failures are never retried for either class.
        endpoint = self.validate_endpoint(endpoint)
        await self._ensure_authenticated()
        generation = self._session_generation
        result = await self._post_json_once(endpoint, payload)
        if result.status == 100:
            await self._login(expected_generation=generation)
            result = await self._post_json_once(endpoint, payload)
        if result.status != 0:
            self._raise_device_status(result, endpoint)
        return result.payload

    async def query(self, payload: JsonObject) -> JsonObject:
        return await self.request(SOCKET_ENDPOINT, payload)

    async def apply(self, payload: JsonObject) -> JsonObject:
        return await self.request(SOCKET_ENDPOINT, payload, mutating=True)

    async def download(
        self,
        endpoint: str,
        payload: JsonObject,
        destination: Path,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> int:
        """Download an authenticated response and return the byte count."""

        endpoint = self.validate_endpoint(endpoint)
        for attempt in range(2):
            await self._ensure_authenticated()
            generation = self._session_generation
            try:
                async with self._http.stream(
                    "POST",
                    endpoint,
                    json=payload,
                    headers=self._authenticated_headers(extra_headers),
                ) as response:
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").lower()
                    if "json" in content_type:
                        body = await response.aread()
                        decoded = self._decode(
                            httpx.Response(response.status_code, content=body), endpoint
                        )
                        if decoded.status == 100 and attempt == 0:
                            await self._login(expected_generation=generation)
                            continue
                        if decoded.status != 0:
                            self._raise_device_status(decoded, endpoint)

                    count = 0
                    with tempfile.NamedTemporaryFile(
                        dir=destination.parent,
                        prefix=f".{destination.name}.",
                        suffix=".part",
                        delete=False,
                    ) as output:
                        temporary = Path(output.name)
                        async for chunk in response.aiter_bytes():
                            output.write(chunk)
                            count += len(chunk)
                    temporary.replace(destination)
                    return count
            except httpx.HTTPError as exc:
                raise DeviceConnectionError(f"WAC510 download from {endpoint} failed") from exc
        raise ProtocolError(f"{endpoint} returned an expired session twice")

    async def upload(
        self,
        endpoint: str,
        source: Path,
        *,
        field_name: str,
        fields: Mapping[str, str] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        """Upload one file to an authenticated multipart endpoint."""

        endpoint = self.validate_endpoint(endpoint)
        for attempt in range(2):
            await self._ensure_authenticated()
            generation = self._session_generation
            try:
                with source.open("rb") as input_file:
                    files = {field_name: (source.name, input_file, "application/octet-stream")}
                    response = await self._http.post(
                        endpoint,
                        data=dict(fields or {}),
                        files=files,
                        headers=self._authenticated_headers(extra_headers),
                    )
                    response.raise_for_status()
            except OSError as exc:
                raise ProtocolError(f"could not read upload file {source.name!r}") from exc
            except httpx.HTTPError as exc:
                raise DeviceConnectionError(f"WAC510 upload to {endpoint} failed") from exc
            result = self._decode(response, endpoint)
            if result.status == 100 and attempt == 0:
                await self._login(expected_generation=generation)
                continue
            if result.status != 0:
                self._raise_device_status(result, endpoint)
            return result.payload
        raise ProtocolError(f"{endpoint} returned an expired session twice")
