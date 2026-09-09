# WAC510 MCP Server Design

## Purpose

Build a local MCP server that gives an AI client broad, efficient control of one NETGEAR WAC510 access point. The server targets the AP at a URL supplied through configuration and authenticates with credentials supplied through environment variables.

The implementation uses Python 3.14, `uv`, FastMCP 4, strict `mypy`, and asynchronous HTTP. It supports the WAC510's undocumented local HTTPS protocol, observed on production firmware V9.9.6.8.

## Scope

The first release provides:

- Typed tools for device information, dashboard data, radios, SSIDs, clients, traffic statistics, network settings, security settings, remote management, logs, and maintenance.
- Named query templates for the AP's major configuration and monitoring domains.
- Raw JSON query and mutation tools that preserve access to firmware operations not yet modeled by a high-level tool.
- Raw endpoint access for the finite set of routes discovered in the firmware's web application.
- File download and multipart upload support for configuration backups, logs, packet captures, configuration restore, and firmware upload.
- Session recovery, response validation, secret redaction, timeouts, and clear MCP errors.
- Local `stdio` transport by default. FastMCP can expose the same server over HTTP when the operator explicitly selects that transport.

The server controls one AP per process. It does not use NETGEAR Insight cloud APIs, SSH, SNMP, device discovery, or credential storage.

## Device Protocol

The stock firmware serves a React application through `lighttpd`. The application sends JSON to `/socketCommunication` and uses specialized routes for sessions, downloads, uploads, firmware, reboot, and factory reset.

Login sends this shape to `/socketCommunication`:

```json
{
  "system": {
    "basicSettings": {
      "adminName": "<username>",
      "adminPasswd": "<password>"
    }
  }
}
```

A successful response has status `0`. The AP returns a `security` response header and an `lhttpdsid` cookie. Subsequent requests send both. Status `100` denotes an expired session. The client reauthenticates once and repeats the request. It never retries a mutation after an ambiguous transport failure.

Most reads send an object whose empty leaf values select fields. Most writes send the same hierarchy with replacement values. The client preserves JSON values exactly because this firmware often represents numbers and booleans as strings.

## Architecture

### Configuration

`Settings` reads only `WAC510_*` environment variables:

- `WAC510_URL`, required, for example `https://192.168.2.31`
- `WAC510_USERNAME`, required
- `WAC510_PASSWORD`, required
- `WAC510_TLS_VERIFY`, default `false`, because the AP uses a self-signed certificate
- `WAC510_CA_BUNDLE`, optional path that enables verification with a private CA
- `WAC510_TIMEOUT_SECONDS`, default `10`
- `WAC510_DOWNLOAD_DIRECTORY`, default current directory

The configuration object hides the password from `repr`, serialization, logs, and errors. The URL must use HTTP or HTTPS, contain no embedded credentials, and omit query strings and fragments.

### Protocol Client

`WAC510Client` owns one persistent `httpx.AsyncClient`, its cookie jar, and the current security token. A lock serializes authentication and session recovery. Normal authenticated requests can share the connection pool. Mutations use the same client but never receive automatic transport retries.

The client exposes these primitives:

- `query(payload)` posts a read selector to `/socketCommunication`.
- `apply(payload)` posts a configuration mutation to `/socketCommunication`.
- `request(endpoint, payload)` accesses an allowlisted JSON route.
- `download(endpoint, payload, destination)` streams a response to an operator-selected file.
- `upload(endpoint, fields, file, field_name)` sends a multipart request.
- `close()` releases sockets and clears session material.

The AP's JSON envelope becomes an `APResponse`. Status `0` succeeds. Other status values raise typed exceptions with the firmware's error code and message. Error rendering redacts password-like keys and security headers.

### Capability Catalogue

A catalogue maps stable names to JSON read selectors. Initial domains cover:

- identity, firmware, system, dashboard, and notifications
- Ethernet, LAN IPv4, wireless WAN, DHCP, VLAN routing, and host bindings
- 2.4 GHz and 5 GHz radios, advanced radio settings, load balancing, QoS, and schedules
- SSIDs, associated clients, bandwidth limits, MAC ACLs, RADIUS, and captive portals
- traffic, interface statistics, trend graphs, URL tracking, neighbor APs, rogue APs, WDS, and packet capture
- syslog, remote management, UPnP, LED control, energy efficiency, users, backups, and firmware state

Each selector is immutable and copied before use. `list_capabilities` returns the catalogue's names and descriptions. `query_capabilities` combines any number of compatible selectors into one payload and one AP round trip.

### MCP Interface

The FastMCP server exposes compact, composable tools:

- `device_info()` returns product and firmware identity.
- `query_capabilities(names)` reads one or more named domains efficiently.
- `list_capabilities()` describes every named read domain.
- `list_clients(limit)` returns recent client records.
- `radio_status()` returns radio state and station counts.
- `traffic_statistics()` returns Ethernet and wireless counters.
- `raw_query(payload)` sends any read selector.
- `apply_configuration(payload, confirm)` applies any configuration payload.
- `raw_request(endpoint, payload, mutating, confirm)` reaches specialized JSON endpoints.
- `download_file(kind, destination, payload)` downloads logs, backups, or packet captures.
- `upload_file(kind, source, fields, confirm)` restores configuration or uploads firmware.
- `reboot(confirm)` reboots the AP.
- `factory_reset(confirm)` restores factory defaults.

High-level mutation helpers can be added without changing the protocol client. Maximum capability comes from the raw tools; named tools improve safety and discoverability.

## Mutation Safety

The server classifies operations as read-only, mutating, disruptive, or destructive.

- Configuration writes require `confirm=true`.
- Raw requests marked `mutating=true` require `confirm=true`.
- Reboot requires `confirm="REBOOT"`.
- Configuration restore requires `confirm="RESTORE_CONFIGURATION"`.
- Firmware upload requires `confirm="UPGRADE_FIRMWARE"`.
- Factory reset requires `confirm="FACTORY_RESET"`.

Failed confirmation returns a preview and performs no AP request. The client rejects unknown raw endpoints. File operations resolve paths and reject missing input files, directories as output targets, and output paths outside `WAC510_DOWNLOAD_DIRECTORY`.

## Error Handling

The MCP layer translates internal failures into concise messages:

- configuration errors identify the invalid variable without exposing its value
- authentication errors distinguish rejected credentials, lockout, and missing security headers
- protocol errors report AP status and error code
- connection errors report the AP host and operation, never credentials or payload secrets
- malformed firmware responses identify the endpoint and expected response type

The server attempts one reauthentication after status `100`. It retries the original request only when the operation is read-only or the AP explicitly rejected it before applying it.

## Efficiency

The server keeps one async connection pool for its lifetime. It merges named selectors so broad status checks use one AP request. It avoids polling, caches only the immutable capability catalogue, and leaves live device data uncached. Downloads stream to disk. Tool responses preserve the AP's JSON without expensive model conversion beyond envelope validation.

## Testing

Tests use `httpx.MockTransport` as a stateful fake AP rather than mocking client methods. They prove:

- login captures the cookie and security header
- concurrent session recovery performs one login
- expired read requests authenticate and retry once
- ambiguous failed mutations do not retry
- response status and malformed JSON become typed errors
- secrets are redacted
- selectors merge without mutation or key loss
- confirmation gates prevent network requests
- upload and download path restrictions hold
- FastMCP exposes the expected tool names and schemas

The completion gates are `uv run pytest`, `uv run mypy src tests`, and a live read-only smoke test against the WAC510. No automated test changes the live AP.

## Documentation

The README explains setup, environment variables, MCP client configuration, tool safety, the self-signed TLS default, test commands, and examples. `.env.example` contains placeholders only. The repository never stores live credentials or session tokens.
