"""Shared JSON types and response validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from wac510_mcp.errors import ProtocolError

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | JsonObject
type JsonObject = dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class APResponse:
    """A validated JSON response from the access point."""

    payload: JsonObject
    status: int

    @classmethod
    def from_json(cls, data: object, endpoint: str) -> APResponse:
        if not isinstance(data, dict):
            raise ProtocolError(f"{endpoint} returned JSON that is not an object")

        payload = cast(JsonObject, data)
        raw_status = payload.get("status", 0)
        try:
            status = int(cast(str | int, raw_status))
        except (TypeError, ValueError) as exc:
            raise ProtocolError(f"{endpoint} returned an invalid status") from exc
        return cls(payload=payload, status=status)


def redact(value: JsonValue) -> JsonValue:
    """Return a deep copy with common secret fields hidden."""

    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, dict):
        return value

    result: JsonObject = {}
    for key, item in value.items():
        normalized = key.lower().replace("_", "")
        if any(word in normalized for word in ("password", "passwd", "passphrase", "secret", "community", "security")):
            result[key] = "[redacted]"
        else:
            result[key] = redact(item)
    return result

