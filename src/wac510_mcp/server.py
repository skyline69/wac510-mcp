"""FastMCP tools for a NETGEAR WAC510."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import httpx
from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.server import Transport
from platformdirs import user_config_path

from wac510_mcp.capabilities import CAPABILITIES, describe_capabilities, merge_capabilities
from wac510_mcp.cli import render_startup_error, render_unexpected_error
from wac510_mcp.client import ALLOWED_ENDPOINTS, WAC510Client
from wac510_mcp.config import Settings
from wac510_mcp.errors import WAC510Error
from wac510_mcp.models import JsonObject, redact
from wac510_mcp.oauth import WAC510OAuthProvider
from wac510_mcp.runtime import DeviceRuntime
from wac510_mcp.storage import EncryptedSettingsStore

type Confirmation = bool | str

_DISRUPTIVE_CONFIRMATIONS: Mapping[str, str] = {
    "/reboot": "REBOOT",
    "/HardFactory": "FACTORY_RESET",
    "/restoreSettings": "RESTORE_CONFIGURATION",
    "/file/firmwareupgrade": "UPGRADE_FIRMWARE",
    "/local_firmware": "UPGRADE_FIRMWARE",
    "/swapfirmware": "UPGRADE_FIRMWARE",
    "/upgradeSFTP": "UPGRADE_FIRMWARE",
}

_DOWNLOAD_ENDPOINTS = frozenset({"/LogFile", "/aplog", "/document", "/xagentlog"})
_UPLOAD_ENDPOINTS = frozenset({"/MACfileUpload", "/file/firmwareupgrade", "/restoreSettings"})
_ALWAYS_MUTATING_ENDPOINTS = frozenset(
    {
        "/HardFactory",
        "/MACfileUpload",
        "/TC_update",
        "/changeUserPassword",
        "/ctsSignup",
        "/file/firmwareupgrade",
        "/forgotPassword",
        "/local_firmware",
        "/logout",
        "/reboot",
        "/restoreSettings",
        "/swapfirmware",
        "/upgradeSFTP",
    }
)


class QuietFastMCP(FastMCP):
    """FastMCP server that always suppresses banners and prettifies fatal errors."""

    async def run_async(
        self,
        transport: Transport | None = None,
        show_banner: bool | None = None,
        **transport_kwargs: Any,
    ) -> None:
        del show_banner
        try:
            await super().run_async(
                transport=transport,
                show_banner=False,
                **transport_kwargs,
            )
        except WAC510Error as error:
            render_startup_error(error)
            raise SystemExit(2) from None
        except Exception as error:
            render_unexpected_error(error)
            raise SystemExit(1) from None


def _get_runtime(ctx: Context) -> DeviceRuntime:
    lifespan_context = cast(Mapping[str, object], ctx.lifespan_context)
    runtime = lifespan_context.get("runtime")
    if not isinstance(runtime, DeviceRuntime):
        raise ToolError("WAC510 runtime is unavailable")
    return runtime


async def _get_client(ctx: Context) -> WAC510Client:
    return await _get_runtime(ctx).client()


async def _get_settings(ctx: Context) -> Settings:
    settings = await _get_runtime(ctx).settings()
    if settings is None:
        raise ToolError("WAC510 is not configured; reconnect through OAuth to open setup")
    return settings


def _normalize_endpoint(endpoint: str) -> str:
    return endpoint if endpoint.startswith("/") else f"/{endpoint}"


def _confirmation_required(endpoint: str, mutating: bool) -> str | None:
    normalized = _normalize_endpoint(endpoint)
    exact = _DISRUPTIVE_CONFIRMATIONS.get(normalized)
    if exact is not None:
        return exact
    return "true" if mutating else None


def _confirmed(actual: Confirmation, required: str) -> bool:
    if required == "true":
        return actual is True or (isinstance(actual, str) and actual.lower() == "true")
    return actual == required


def _preview(operation: str, payload: JsonObject, required: str) -> JsonObject:
    return {
        "performed": False,
        "operation": operation,
        "required_confirmation": required,
        "payload": redact(payload),
    }


def _resolve_inside(base: Path, raw_path: str, *, must_exist: bool) -> Path:
    base = base.resolve()
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = candidate.resolve()
    if not candidate.is_relative_to(base):
        raise ToolError(f"path must stay inside {base}")
    if must_exist and not candidate.is_file():
        raise ToolError(f"input file does not exist: {candidate.name}")
    if not must_exist:
        if candidate.exists() and candidate.is_dir():
            raise ToolError("download destination must be a file")
        candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def create_server(
    settings: Settings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    oauth_base_url: str | None = None,
    config_directory: Path | None = None,
) -> FastMCP:
    """Create a server, optionally with injected settings and HTTP transport."""

    store = EncryptedSettingsStore(
        config_directory or user_config_path("wac510-mcp", ensure_exists=False)
    )
    runtime = DeviceRuntime(store, initial_settings=settings, transport=transport)
    auth = (
        WAC510OAuthProvider(base_url=oauth_base_url, runtime=runtime)
        if oauth_base_url is not None
        else None
    )

    @asynccontextmanager
    async def app_lifespan(_server: FastMCP) -> AsyncIterator[dict[str, object]]:
        try:
            yield {"runtime": runtime}
        finally:
            await runtime.aclose()

    server = QuietFastMCP(
        "NETGEAR WAC510",
        instructions=(
            "Manage one NETGEAR WAC510 through its local HTTPS interface. "
            "Prefer named read capabilities. Preview every mutation before confirming it."
        ),
        version="0.1.0",
        lifespan=app_lifespan,
        auth=auth,
        on_duplicate="error",
    )

    @server.tool
    async def list_capabilities() -> JsonObject:
        """List named read selectors and the fields each selector requests."""

        return describe_capabilities()

    @server.tool
    async def list_endpoints() -> JsonObject:
        """List raw HTTP routes discovered in the WAC510 V9.9.6.8 web UI."""

        return {
            "endpoints": list(sorted(ALLOWED_ENDPOINTS)),
            "disruptive_confirmations": dict(_DISRUPTIVE_CONFIRMATIONS),
        }

    @server.tool
    async def device_info(ctx: Context) -> JsonObject:
        """Read product, firmware, serial, and firmware-channel information."""

        client = await _get_client(ctx)
        return await client.query(deepcopy(CAPABILITIES["identity"].selector))

    @server.tool
    async def query_capabilities(names: list[str], ctx: Context) -> JsonObject:
        """Read named domains concurrently and return each firmware response by name."""

        unique_names = list(dict.fromkeys(names))
        selectors = [(name, merge_capabilities([name])) for name in unique_names]
        semaphore = asyncio.Semaphore(4)

        async def query_one(selector: JsonObject) -> JsonObject:
            async with semaphore:
                client = await _get_client(ctx)
                return await client.query(selector)

        responses = await asyncio.gather(*(query_one(selector) for _, selector in selectors))
        return {
            "capabilities": {
                name: response
                for (name, _), response in zip(selectors, responses, strict=True)
            }
        }

    @server.tool
    async def list_clients(ctx: Context, limit: int = 5) -> JsonObject:
        """Read recent wireless clients. The firmware supports limits from 1 through 100."""

        if not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        selector: JsonObject = {"system": {"monitor": {"recentCliList": {str(limit): ""}}}}
        client = await _get_client(ctx)
        return await client.query(selector)

    @server.tool
    async def radio_status(ctx: Context) -> JsonObject:
        """Read radio enablement, supported bands, and station counts."""

        client = await _get_client(ctx)
        return await client.query(deepcopy(CAPABILITIES["radio_status"].selector))

    @server.tool
    async def traffic_statistics(ctx: Context) -> JsonObject:
        """Read Ethernet and Wi-Fi packet and byte counters."""

        client = await _get_client(ctx)
        return await client.query(deepcopy(CAPABILITIES["traffic"].selector))

    @server.tool
    async def raw_query(payload: JsonObject, ctx: Context) -> JsonObject:
        """Send an arbitrary read selector through /socketCommunication."""

        client = await _get_client(ctx)
        return await client.query(payload)

    @server.tool
    async def apply_configuration(
        payload: JsonObject,
        ctx: Context,
        confirm: bool = False,
    ) -> JsonObject:
        """Preview or apply an arbitrary configuration payload. Set confirm=true to apply."""

        if not confirm:
            return _preview("apply_configuration", payload, "true")
        client = await _get_client(ctx)
        result = await client.apply(payload)
        return {"performed": True, "response": result}

    @server.tool
    async def raw_request(
        endpoint: str,
        payload: JsonObject,
        ctx: Context,
        mutating: bool = False,
        confirm: Confirmation = False,
    ) -> JsonObject:
        """Call an allowlisted firmware route. Mark writes as mutating and confirm them."""

        normalized = _normalize_endpoint(endpoint)
        WAC510Client.validate_endpoint(normalized)
        if normalized == "/socketCommunication":
            raise ToolError("use raw_query for reads or apply_configuration for writes")
        effective_mutating = mutating or normalized in _ALWAYS_MUTATING_ENDPOINTS
        required = _confirmation_required(normalized, effective_mutating)
        if required is not None and not _confirmed(confirm, required):
            return _preview(normalized, payload, required)
        client = await _get_client(ctx)
        return await client.request(normalized, payload, mutating=effective_mutating)

    @server.tool
    async def download_file(
        endpoint: str,
        destination: str,
        payload: JsonObject,
        ctx: Context,
        extra_headers: dict[str, str] | None = None,
    ) -> JsonObject:
        """Download logs, configuration, or packet captures into the configured directory."""

        normalized = _normalize_endpoint(endpoint)
        if normalized not in _DOWNLOAD_ENDPOINTS:
            valid = ", ".join(sorted(_DOWNLOAD_ENDPOINTS))
            raise ToolError(f"download endpoint must be one of: {valid}")
        active_settings = await _get_settings(ctx)
        path = _resolve_inside(active_settings.download_directory, destination, must_exist=False)
        client = await _get_client(ctx)
        size = await client.download(
            normalized,
            payload,
            path,
            extra_headers=extra_headers,
        )
        return {"path": str(path), "bytes": size}

    @server.tool
    async def upload_file(
        endpoint: str,
        source: str,
        field_name: str,
        ctx: Context,
        fields: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
        confirm: Confirmation = False,
    ) -> JsonObject:
        """Upload restore or firmware data after the endpoint-specific confirmation."""

        normalized = _normalize_endpoint(endpoint)
        if normalized not in _UPLOAD_ENDPOINTS:
            valid = ", ".join(sorted(_UPLOAD_ENDPOINTS))
            raise ToolError(f"upload endpoint must be one of: {valid}")
        required = _DISRUPTIVE_CONFIRMATIONS.get(normalized, "true")
        empty_payload: JsonObject = {"source": Path(source).name, "field_name": field_name}
        if not _confirmed(confirm, required):
            return _preview(normalized, empty_payload, required)
        active_settings = await _get_settings(ctx)
        path = _resolve_inside(active_settings.download_directory, source, must_exist=True)
        client = await _get_client(ctx)
        response = await client.upload(
            normalized,
            path,
            field_name=field_name,
            fields=fields,
            extra_headers=extra_headers,
        )
        return {"performed": True, "response": response}

    @server.tool
    async def reboot(ctx: Context, confirm: str = "") -> JsonObject:
        """Reboot the AP. Pass the exact confirmation token REBOOT."""

        payload: JsonObject = {"reboot": 1}
        if confirm != "REBOOT":
            return _preview("/reboot", payload, "REBOOT")
        client = await _get_client(ctx)
        response = await client.request("/reboot", payload, mutating=True)
        return {"performed": True, "response": response}

    @server.tool
    async def factory_reset(ctx: Context, confirm: str = "") -> JsonObject:
        """Erase AP configuration and restart. Pass the exact token FACTORY_RESET."""

        payload: JsonObject = {"hardFactoryReset": 1}
        if confirm != "FACTORY_RESET":
            return _preview("/HardFactory", payload, "FACTORY_RESET")
        client = await _get_client(ctx)
        response = await client.request("/HardFactory", payload, mutating=True)
        return {"performed": True, "response": response}

    return server


_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8000
_DEFAULT_BASE_URL = f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}"

mcp = create_server(oauth_base_url=_DEFAULT_BASE_URL)


def main() -> None:
    """Run the OAuth-protected HTTP MCP server."""

    try:
        mcp.run(
            transport="http",
            host=_DEFAULT_HOST,
            port=_DEFAULT_PORT,
            show_banner=False,
        )
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except WAC510Error as error:
        render_startup_error(error)
        raise SystemExit(2) from None
    except Exception as error:
        render_unexpected_error(error)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
