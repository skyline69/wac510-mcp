from __future__ import annotations

from copy import deepcopy

import pytest

from wac510_mcp.capabilities import CAPABILITIES, merge_capabilities
from wac510_mcp.errors import ProtocolError


def test_merge_capabilities_combines_fields_without_mutating_catalogue() -> None:
    before = deepcopy(CAPABILITIES["identity"].selector)
    payload = merge_capabilities(["identity", "radio_status"])
    system = payload["system"]
    assert isinstance(system, dict)
    monitor = system["monitor"]
    assert isinstance(monitor, dict)
    assert monitor["productId"] == ""
    assert "radioApStatus" in monitor
    assert CAPABILITIES["identity"].selector == before


def test_merge_capabilities_rejects_unknown_name() -> None:
    with pytest.raises(ProtocolError, match="valid names"):
        merge_capabilities(["missing"])


def test_merge_capabilities_rejects_empty_list() -> None:
    with pytest.raises(ProtocolError, match="at least one"):
        merge_capabilities([])

