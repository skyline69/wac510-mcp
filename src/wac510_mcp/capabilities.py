"""Named read selectors for the WAC510 object protocol."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType

from wac510_mcp.errors import ProtocolError
from wac510_mcp.models import JsonObject, JsonValue


@dataclass(frozen=True, slots=True)
class Capability:
    description: str
    selector: JsonObject


_CAPABILITIES: dict[str, Capability] = {
    "identity": Capability(
        "Product, production firmware, serial number, and firmware type.",
        {"system": {"monitor": {"productId": "", "sysVersion": "", "fwType": ""}}},
    ),
    "basic_settings": Capability(
        "AP name, operating mode, country, cloud state, and VLAN settings.",
        {"system": {"monitor": {"countryList": ""}, "basicSettings": {"apName": "", "deviceMode": "", "sysCountryRegion": "", "cloudStatus": "", "untaggedVlanID": "", "managementVlanID": ""}}},
    ),
    "recent_clients": Capability(
        "Five most recently observed wireless clients.",
        {"system": {"monitor": {"recentCliList": {"5": ""}}}},
    ),
    "client_lists": Capability(
        "Connected wired and wireless client tables.",
        {"system": {"monitor": {"wirelessClient": "", "wiredClient": ""}}},
    ),
    "traffic": Capability(
        "Ethernet and radio packet and byte counters.",
        {"system": {"monitor": {"stats": {"lan": {"lanRecvPacket": "", "lanTransPacket": "", "lanRecvBytes": "", "lanTransBytes": ""}, "wlan0": {"wlanRecvPacket": "", "wlanTransPacket": "", "wlanRecvBytes": "", "wlanTransBytes": ""}, "wlan1": {"wlanRecvPacket": "", "wlanTransPacket": "", "wlanRecvBytes": "", "wlanTransBytes": ""}}}}},
    ),
    "radio_status": Capability(
        "Radio enablement, station counts, and 5 GHz support.",
        {"system": {"monitor": {"radioApStatus": {"wlan0": {"numberOfStations": ""}, "wlan1": {"numberOfStations": ""}}, "FiveGhzSupport": {"wlan1": ""}}, "wlanSettings": {"wlanSettingTable": {"wlan0": {"radioStatus": ""}, "wlan1": {"radioStatus": ""}}}}},
    ),
    "radio_details": Capability(
        "Configured 2.4 GHz and 5 GHz radio settings.",
        {"system": {"basicSettings": {"scheduledWirelessStatus": ""}, "monitor": {"channelWidth": {"wlan0": "", "wlan1": ""}, "operateMode": {"wlan0": "", "wlan1": ""}, "currentChannel": {"wlan0": "", "wlan1": ""}, "radioApStatus": {"wlan0": {"numberOfStations": ""}, "wlan1": {"numberOfStations": ""}}, "stats": {"wlan0": {"traffic": ""}, "wlan1": {"traffic": ""}}}, "wlanSettings": {"wlanSettingTable": {"wlan0": {"radioStatus": ""}, "wlan1": {"radioStatus": ""}}}}},
    ),
    "ssids": Capability(
        "SSID profiles and their radio assignments.",
        {"system": {"wlanSettings": {"wlanSettingTable": {"ssidGetDetails": ""}}}},
    ),
    "trends": Capability(
        "Current traffic, band, and SSID trend graphs.",
        {"system": {"monitor": {"currentTrendGraph": {"traffic_dist": "", "band_graph": "", "ssid_graph": ""}}}},
    ),
    "network": Capability(
        "LAN IPv4, Ethernet, DHCP server, and router-mode settings.",
        {"system": {"basicSettings": {"deviceMode": "", "dhcpClientStatus": "", "ipAddr": "", "netmaskAddr": "", "gatewayAddr": "", "priDnsAddr": "", "sndDnsAddr": "", "networkIntegralityCheck": "", "untaggedVlanStatus": "", "untaggedVlanID": "", "managementVlanID": "", "interVlanRouting": "", "fqdn": ""}, "monitor": {"ipAddress": "", "subNetMask": "", "defaultGateway": "", "primaryDNS": "", "secondaryDNS": ""}}},
    ),
    "security": Capability(
        "Layer 2 security, RADIUS, MAC ACL, and URL filtering settings.",
        {"system": {"l2Security": {"l2SecurityStatus": ""}, "info802dot1x": {"authinfo": {"priRadIpAddr": "", "priRadPort": "", "priRadSharedSecret": "", "sndRadIpAddr": "", "sndRadPort": "", "sndRadSharedSecret": ""}, "accntinfo": {"priAcntIpAddr": "", "priAcntPort": "", "priAcntSharedSecret": "", "sndAcntIpAddr": "", "sndAcntPort": "", "sndAcntSharedSecret": ""}, "authSetting": {"reauthTime": "", "wpaGroupKeyUpdateCondition": "", "wpaGroupKeyUpdateIntervalSecond": ""}}}},
    ),
    "remote_management": Capability(
        "SSH, Telnet, SNMP, and related remote-management settings.",
        {"system": {"remoteSettings": {"snmpStatus": "", "readOnlyCommunity": "", "readWriteCommunity": "", "trapServerCommunity": "", "trapServerIP": "", "trapPort": ""}}},
    ),
    "syslog": Capability(
        "Syslog configuration and log state.",
        {"system": {"logSettings": {"syslogStatus": "", "syslogSrvIp": "", "syslogSrvPort": ""}}},
    ),
    "neighbors": Capability(
        "Neighbor and rogue access-point observations.",
        {"system": {"monitor": {"neighborApDetail": "", "rogueAp": ""}}},
    ),
    "wds": Capability(
        "Wireless distribution and bridge configuration.",
        {"system": {"monitor": {"wdsLink": {"wlan0": {"wds0": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds1": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds2": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds3": {"wdsProfileStatus": "", "wdsProfileName": ""}}, "wlan1": {"wds0": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds1": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds2": {"wdsProfileStatus": "", "wdsProfileName": ""}, "wds3": {"wdsProfileStatus": "", "wdsProfileName": ""}}}}}},
    ),
    "schedules": Capability(
        "Wireless and reboot schedules.",
        {"system": {"basicSettings": {"schReboot": "", "rbDays": "", "rbTime0": "", "rbTime1": "", "rbTime2": "", "rbTime3": "", "rbTime4": "", "rbTime5": "", "rbTime6": ""}}},
    ),
    "maintenance": Capability(
        "LED, energy, packet capture, backup, and firmware state.",
        {"system": {"pktCaptureSettings": {"interface": "", "duration": "", "maxSize": "", "beaconCapture": "", "promiscousCapture": "", "clientMacFilter": "", "clientMacAddress": ""}, "FwUpdate": {"ImageAvailable": "", "ImageVersion": "", "LastcheckedDate": "", "releasenotesurl": ""}, "monitor": {"diskusage": ""}}},
    ),
    "users": Capability(
        "Local management users and account types.",
        {"system": {"userSettings": {"user1": "", "user1status": "", "user2": "", "user2status": "", "user3": "", "user3status": "", "user4": "", "user4status": ""}}},
    ),
}

CAPABILITIES: Mapping[str, Capability] = MappingProxyType(_CAPABILITIES)


def _merge(target: JsonObject, source: JsonObject, path: str = "") -> None:
    for key, value in source.items():
        child_path = f"{path}.{key}" if path else key
        if key not in target:
            target[key] = deepcopy(value)
            continue
        current = target[key]
        if isinstance(current, dict) and isinstance(value, dict):
            _merge(current, value, child_path)
        elif current != value:
            raise ProtocolError(f"capability selectors conflict at {child_path}")


def merge_capabilities(names: Sequence[str]) -> JsonObject:
    """Merge named selectors into one device query."""

    if not names:
        raise ProtocolError("at least one capability name is required")
    merged: JsonObject = {}
    for name in dict.fromkeys(names):
        capability = CAPABILITIES.get(name)
        if capability is None:
            valid = ", ".join(sorted(CAPABILITIES))
            raise ProtocolError(f"unknown capability {name!r}; valid names: {valid}")
        _merge(merged, capability.selector)
    return merged


def describe_capabilities() -> JsonObject:
    return {
        name: {"description": capability.description, "selector": deepcopy(capability.selector)}
        for name, capability in CAPABILITIES.items()
    }
