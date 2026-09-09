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

## Configuration

Set these variables in the MCP client's environment. Do not commit a populated `.env` file.

```bash
WAC510_URL=https://192.168.2.31
WAC510_USERNAME=admin
WAC510_PASSWORD=replace-me
WAC510_TLS_VERIFY=false
WAC510_TIMEOUT_SECONDS=10
WAC510_DOWNLOAD_DIRECTORY=./downloads
```

`WAC510_TLS_VERIFY` defaults to `false` because the AP normally uses a self-signed certificate. Set it to `true` for a publicly trusted certificate, or set `WAC510_CA_BUNDLE` to a private CA file.

## Run

Run the default stdio server:

```bash
uv run wac510-mcp
```

Example MCP configuration:

```json
{
  "mcpServers": {
    "wac510": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/wac510-mcp", "run", "wac510-mcp"],
      "env": {
        "WAC510_URL": "https://192.168.2.31",
        "WAC510_USERNAME": "admin",
        "WAC510_PASSWORD": "replace-me"
      }
    }
  }
}
```

The server always hides FastMCP's startup banner, including when it runs through FastMCP's generic CLI:

```bash
uv run fastmcp run src/wac510_mcp/server.py:mcp
```

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

The live test suite is read-only and opt-in:

```bash
WAC510_LIVE_TEST=1 uv run pytest tests/test_live_readonly.py -q
```
