"""Local OAuth authorization flow with AP configuration."""

from __future__ import annotations

import html
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from wac510_mcp.config import Settings
from wac510_mcp.errors import WAC510Error
from wac510_mcp.runtime import DeviceRuntime

_AUTH_REQUEST_TTL_SECONDS = 15 * 60


@dataclass(frozen=True, slots=True)
class PendingAuthorization:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float


def _field(form: FormData, name: str) -> str:
    value = form.get(name)
    return value if isinstance(value, str) else ""


def _page(
    *,
    request_id: str | None,
    settings: Settings | None,
    error: str | None = None,
    error_title: str = "Setup could not be saved.",
    submitted: FormData | None = None,
) -> str:
    def value(name: str, fallback: str = "") -> str:
        raw = _field(submitted, name) if submitted is not None else fallback
        return html.escape(raw, quote=True)

    url = value("url", settings.url if settings else "")
    username = value("username", settings.username if settings else "admin")
    timeout = value("timeout_seconds", str(settings.timeout_seconds) if settings else "10")
    ca_bundle = value("ca_bundle", str(settings.ca_bundle) if settings and settings.ca_bundle else "")
    download_directory = value(
        "download_directory",
        str(settings.download_directory) if settings else "./downloads",
    )
    tls_checked = (
        _field(submitted, "tls_verify") == "on"
        if submitted is not None
        else bool(settings and settings.tls_verify)
    )
    request_field = html.escape(request_id or "", quote=True)
    error_html = (
        f'<div class="error" role="alert"><strong>{html.escape(error_title)}</strong> {html.escape(error)}</div>'
        if error
        else ""
    )
    disabled = "" if request_id else " disabled"
    controls_hidden = " hidden" if request_id is None and error is not None else ""
    button_label = "Save & authorize" if request_id else "Start from your MCP client"
    password_hint = "Leave blank to keep the saved password." if settings else "Stored encrypted after verification."

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAC510 MCP</title>
  <style>
    :root {{ color-scheme: light; --paper:#f6f6f4; --ink:#202124; --muted:#6b7075; --line:#d7d8d5; --signal:#147d9e; --signal-dark:#0e647f; --danger:#a23232; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; min-height:100vh; background:var(--paper); color:var(--ink); font-family:"Avenir Next","Segoe UI",sans-serif; }}
    main {{ width:min(620px,calc(100% - 32px)); margin:0 auto; padding:64px 0; }}
    header {{ margin-bottom:28px; }}
    h1 {{ margin:0; font-size:38px; font-weight:650; line-height:1.1; }}
    .intro {{ max-width:520px; margin:12px 0 0; color:var(--muted); font-size:16px; line-height:1.55; }}
    form {{ padding:28px; border:1px solid var(--line); border-radius:9px; background:#fff; box-shadow:0 8px 30px rgba(20,24,28,.05); }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
    .wide {{ grid-column:1/-1; }}
    label {{ display:block; margin:0 0 7px; font-size:13px; font-weight:650; }}
    input {{ width:100%; min-height:44px; padding:10px 12px; border:1px solid #b9b8b3; border-radius:6px; background:#fff; color:var(--ink); font:inherit; font-size:15px; outline:none; transition:border-color .16s,box-shadow .16s; }}
    input:focus {{ border-color:var(--signal); box-shadow:0 0 0 3px rgba(8,126,164,.13); }}
    .hint {{ margin:7px 0 0; color:var(--muted); font-size:12px; line-height:1.4; }}
    details {{ margin-top:22px; padding-top:18px; border-top:1px solid var(--line); }}
    summary {{ cursor:pointer; font-size:13px; font-weight:700; }}
    details .grid {{ margin-top:18px; }}
    .check {{ display:flex; align-items:center; gap:10px; min-height:44px; margin-top:22px; }}
    .check input {{ width:17px; min-height:17px; accent-color:var(--signal); }}
    .check label {{ margin:0; }}
    .error {{ margin:0 0 20px; padding:13px 15px; border-left:3px solid var(--danger); background:#fff0f0; color:#702323; font-size:13px; line-height:1.45; }}
    button {{ width:100%; margin-top:24px; min-height:48px; border:0; border-radius:6px; background:var(--signal); color:white; font-size:14px; font-weight:700; cursor:pointer; transition:background .16s; }}
    button:hover:not(:disabled) {{ background:var(--signal-dark); }}
    button:disabled {{ background:#a8aaac; cursor:not-allowed; }}
    footer {{ margin-top:18px; color:var(--muted); font-size:12px; line-height:1.5; }}
    @media (max-width:620px) {{ main {{ padding:36px 0; }} form {{ padding:21px; }} .grid {{ grid-template-columns:1fr; }} .wide {{ grid-column:auto; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>WAC510 MCP</h1>
      <p class="intro">Configure the NETGEAR access point used by this MCP server. The connection is verified before authorization completes.</p>
    </header>
    <form method="post" action="/setup">
      <input type="hidden" name="request" value="{request_field}">
      {error_html}
      <div class="grid"{controls_hidden}>
        <div class="wide">
          <label for="url">Access point URL</label>
          <input id="url" name="url" type="url" required value="{url}" placeholder="https://192.168.2.31" autocomplete="url">
        </div>
        <div>
          <label for="username">Username</label>
          <input id="username" name="username" required value="{username}" autocomplete="username">
        </div>
        <div>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password"{' required' if settings is None else ''}>
          <p class="hint">{password_hint}</p>
        </div>
      </div>
      <details{controls_hidden}>
        <summary>Advanced connection settings</summary>
        <div class="grid">
          <div>
            <label for="timeout_seconds">Timeout in seconds</label>
            <input id="timeout_seconds" name="timeout_seconds" type="number" min="1" max="120" step="0.5" value="{timeout}">
          </div>
          <div class="check">
            <input id="tls_verify" name="tls_verify" type="checkbox"{' checked' if tls_checked else ''}>
            <label for="tls_verify">Verify TLS certificate</label>
          </div>
          <div class="wide">
            <label for="ca_bundle">Private CA bundle path</label>
            <input id="ca_bundle" name="ca_bundle" value="{ca_bundle}" placeholder="Optional">
          </div>
          <div class="wide">
            <label for="download_directory">Download directory</label>
            <input id="download_directory" name="download_directory" value="{download_directory}">
          </div>
        </div>
      </details>
      <button type="submit"{disabled}{controls_hidden}>{button_label}</button>
    </form>
    <footer>Credentials are sent only to the configured AP and stored in an encrypted local settings file.</footer>
  </main>
</body>
</html>"""


def _html_response(content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        content,
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


class WAC510OAuthProvider(InMemoryOAuthProvider):
    """Local OAuth provider whose authorization page configures the AP."""

    def __init__(self, *, base_url: str, runtime: DeviceRuntime) -> None:
        normalized_base_url = base_url.rstrip("/")
        super().__init__(
            base_url=normalized_base_url,
            service_documentation_url=f"{normalized_base_url}/setup",
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["wac510"],
                default_scopes=["wac510"],
            ),
            required_scopes=["wac510"],
        )
        self._public_base_url = normalized_base_url
        self._runtime = runtime
        self._pending: dict[str, PendingAuthorization] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        self._pending = {
            request_id: pending
            for request_id, pending in self._pending.items()
            if pending.expires_at > now
        }

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        self._prune()
        request_id = secrets.token_urlsafe(32)
        self._pending[request_id] = PendingAuthorization(
            client=client,
            params=params,
            expires_at=time.monotonic() + _AUTH_REQUEST_TTL_SECONDS,
        )
        return f"{self._public_base_url}/setup?{urlencode({'request': request_id})}"

    async def _setup(self, request: Request) -> Response:
        self._prune()
        if request.method == "POST":
            form = await request.form(max_files=0, max_fields=12)
            request_id = _field(form, "request")
        else:
            form = None
            request_id = request.query_params.get("request", "")

        pending = self._pending.get(request_id)
        try:
            current = await self._runtime.settings()
        except WAC510Error as error:
            return _html_response(
                _page(
                    request_id=request_id if pending is not None else None,
                    settings=None,
                    error=str(error),
                    submitted=form,
                ),
                status_code=500,
            )
        if pending is None:
            return _html_response(
                _page(
                    request_id=None,
                    settings=None,
                    error=(
                        "Return to your terminal and start the MCP login again."
                        if request_id
                        else None
                    ),
                    error_title="Authorization request expired.",
                ),
                status_code=410 if request_id else 200,
            )
        if form is None:
            return _html_response(_page(request_id=request_id, settings=current))

        password = _field(form, "password") or (current.password if current else "")
        try:
            settings = Settings.from_values(
                url=_field(form, "url"),
                username=_field(form, "username"),
                password=password,
                tls_verify=_field(form, "tls_verify") == "on",
                ca_bundle=_field(form, "ca_bundle") or None,
                timeout_seconds=_field(form, "timeout_seconds") or "10",
                download_directory=_field(form, "download_directory") or "./downloads",
            )
            await self._runtime.configure(settings)
        except WAC510Error as error:
            return _html_response(
                _page(
                    request_id=request_id,
                    settings=current,
                    error=str(error),
                    submitted=form,
                ),
                status_code=400,
            )

        self._pending.pop(request_id, None)
        redirect_url = await super().authorize(pending.client, pending.params)
        return RedirectResponse(redirect_url, status_code=303)

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        return [
            *super().get_routes(mcp_path),
            Route("/", self._setup, methods=["GET"], name="wac510-home"),
            Route("/setup", self._setup, methods=["GET", "POST"], name="wac510-setup"),
        ]
