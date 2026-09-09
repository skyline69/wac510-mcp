# WAC510 MCP

A local [FastMCP](https://gofastmcp.com/) server for one NETGEAR WAC510 access point. It talks directly to the stock firmware's local HTTPS interface and keeps one asynchronous connection pool open for efficient calls.

The WAC510 protocol is undocumented. This implementation was validated against production firmware V9.9.6.8.

The server targets one AP per process. It does not use NETGEAR Insight, SSH, or SNMP.

## Requirements

- Python 3.14.7
- [uv](https://docs.astral.sh/uv/)
- A WAC510 reachable through its local management URL

Expected startup failures are rendered as concise [Rich](https://rich.readthedocs.io/) panels with corrective guidance. Unexpected programming errors retain their tracebacks.

Install the locked environment:

```bash
uv sync
```

After the first PyPI release, run the server without cloning the repository:

```bash
uvx wac510-mcp
```

## Run

Start the local OAuth-protected HTTP server:

```bash
uv run wac510-mcp
```

Connect your MCP client to:

```text
http://127.0.0.1:8000/mcp
```

The MCP client's OAuth flow opens a page titled **WAC510 MCP**. Enter the access point URL, username, password, and optional connection settings. The server verifies that the device is a WAC510 before authorization completes.

Example URL-based MCP configuration:

```json
{
  "mcpServers": {
    "wac510": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

The server always hides FastMCP's startup banner. No environment variable or launch flag is required.

## Add to Codex

First, keep the server running in a terminal:

```bash
uvx wac510-mcp@latest
```

In another terminal, add its Streamable HTTP endpoint and start OAuth:

```bash
codex mcp add wac510 --url http://127.0.0.1:8000/mcp
codex mcp login wac510 --oauth-client-registration dcr
```

Your browser opens the **WAC510 MCP** setup page. Enter the AP connection settings and authorize the client. Confirm the connection with:

```bash
codex mcp list
```

You can also enter `/mcp` inside Codex to inspect the server and its tools. Codex CLI, the IDE extension, and the desktop app share the same MCP configuration. See the [official OpenAI MCP documentation](https://developers.openai.com/codex/mcp).

## Add to Claude Code

Keep `uvx wac510-mcp@latest` running, then add the server at user scope so it is available in every project:

```bash
claude mcp add \
  --transport http \
  --scope user \
  wac510 \
  http://127.0.0.1:8000/mcp
```

Open Claude Code and enter:

```text
/mcp
```

Select `wac510`, authenticate, and complete the setup page in your browser. Verify the saved configuration with:

```bash
claude mcp get wac510
```

See the [official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

The OAuth transport is HTTP, not stdio. Both clients connect to the running URL; they do not launch `uvx` through a `command` entry. The server listens only on this machine by default.

## Stored settings

Settings are saved under the platform's user configuration directory. On Linux, the default location is:

```text
~/.config/wac510-mcp/
```

`settings.enc` contains the encrypted AP configuration, `oauth.enc` contains OAuth client registrations and tokens, and `settings.key` contains their local encryption key. All files use owner-only permissions, and the password is never rendered back into the setup page. OAuth access and refresh tokens survive server restarts while retaining expiration, client binding, rotation, and revocation behavior.

TLS verification defaults to off because the AP normally uses a self-signed certificate. The setup page can enable verification or specify a private CA bundle.

## Safety

Read tools run immediately. Configuration writes require `confirm=true`. Disruptive operations require the exact tokens returned in their tool descriptions:

- `REBOOT`
- `RESTORE_CONFIGURATION`
- `UPGRADE_FIRMWARE`
- `FACTORY_RESET`

The raw tools make the server maximally capable. They expose the AP's private JSON protocol, so inspect a read payload before applying it.

For example, read an arbitrary firmware field with `raw_query`:

```json
{
  "payload": {
    "system": {
      "basicSettings": {
        "apName": ""
      }
    }
  }
}
```

Pass the returned hierarchy with changed leaf values to `apply_configuration` first without confirmation. Review its redacted preview, then repeat the call with `confirm=true`.

## Tools

- `list_capabilities` and `list_endpoints` describe the reverse-engineered surface.
- `device_info`, `list_clients`, `radio_status`, and `traffic_statistics` provide common reads.
- `query_capabilities` reads any selection of 18 management domains with bounded concurrency.
- `raw_query` accepts any `/socketCommunication` read selector.
- `apply_configuration` applies arbitrary configuration after a preview and confirmation.
- `raw_request` calls any discovered JSON endpoint with endpoint-specific confirmation.
- `download_file` and `upload_file` support logs, configuration, packet captures, ACL files, restore, and firmware files.
- `reboot` and `factory_reset` require exact confirmation tokens.

## Development

```bash
uv run pytest
uv run mypy src tests
```

## Releasing

The release workflow publishes a new version to PyPI, creates a matching GitHub Release, attaches the wheel and source archive, and adds provenance attestations. Start a patch release from any clean checkout with:

```bash
just release
```

Choose another semantic version increment when needed:

```bash
just release minor
just release major
```

The recipe updates `main`, runs the local gate, bumps `pyproject.toml` and `uv.lock`, pushes `main`, fast-forwards and pushes `release`, then switches the checkout back to `main`. Use `just sync-release` to synchronize the branches without changing the version.

The live test suite is read-only and opt-in. Its environment variables exist only for automated testing; normal users configure the server through OAuth:

```bash
WAC510_LIVE_TEST=1 uv run pytest tests/test_live_readonly.py -q
```
