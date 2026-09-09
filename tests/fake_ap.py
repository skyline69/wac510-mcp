"""Stateful HTTP transport that models the observed WAC510 protocol."""

from __future__ import annotations

import json
from typing import cast

import httpx

from wac510_mcp.client import WAC510Client
from wac510_mcp.config import Settings
from wac510_mcp.models import JsonObject


class FakeAP:
    def __init__(self) -> None:
        self.login_count = 0
        self.logout_count = 0
        self.authenticated_requests = 0
        self.mutation_attempts = 0
        self.upload_count = 0
        self.expire_next_request = False
        self.fail_next_mutation = False
        self.last_cookie = ""
        self._token = ""
        self.bootstrap_count = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/":
            self.bootstrap_count += 1
            return httpx.Response(
                200,
                headers={"set-cookie": "lhttpdsid=fake; Path=/; HttpOnly"},
                text="login",
                request=request,
            )
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            self.last_cookie = request.headers.get("cookie", "")
            if request.headers.get("security") != self._token:
                return httpx.Response(200, json={"status": 100}, request=request)
            if self.expire_next_request:
                self.expire_next_request = False
                return httpx.Response(200, json={"status": 100}, request=request)
            self.authenticated_requests += 1
            self.mutation_attempts += 1
            self.upload_count += 1
            return httpx.Response(200, json={"status": 0}, request=request)
        raw = json.loads(request.content)
        payload = cast(JsonObject, raw)
        basic = payload.get("system")
        if isinstance(basic, dict):
            basic_settings = basic.get("basicSettings")
            if isinstance(basic_settings, dict) and "adminName" in basic_settings:
                return self._login(request, basic_settings)

        self.last_cookie = request.headers.get("cookie", "")
        if request.headers.get("security") != self._token:
            return httpx.Response(200, json={"status": 100}, request=request)
        if self.expire_next_request:
            self.expire_next_request = False
            return httpx.Response(200, json={"status": 100}, request=request)

        if request.url.path == "/logout":
            self.logout_count += 1
            self._token = ""
            return httpx.Response(200, json={"status": 0}, request=request)

        self.authenticated_requests += 1
        is_mutation = self._is_mutation(request.url.path, payload)
        if is_mutation:
            self.mutation_attempts += 1
            if self.fail_next_mutation:
                self.fail_next_mutation = False
                raise httpx.ConnectError("simulated disconnect", request=request)

        return httpx.Response(200, json=self._response_for(request.url.path, payload), request=request)

    def _login(self, request: httpx.Request, basic_settings: JsonObject) -> httpx.Response:
        self.login_count += 1
        cookie = request.headers.get("cookie", "")
        if (
            "lhttpdsid=fake" not in cookie
            or basic_settings.get("adminName") != "admin"
            or basic_settings.get("adminPasswd") != "secret"
        ):
            return httpx.Response(
                200,
                json={"status": 1, "data": {"err_code": 26, "err_mesg": "Invalid username"}},
                request=request,
            )
        self._token = f"security-{self.login_count}"
        return httpx.Response(
            200,
            headers={"security": self._token, "set-cookie": "lhttpdsid=fake; Path=/; HttpOnly"},
            json={"status": 0, "system": {"basicSettings": {"accountType": "1"}}},
            request=request,
        )

    @staticmethod
    def _is_mutation(path: str, payload: JsonObject) -> bool:
        if path in {"/reboot", "/HardFactory", "/restoreSettings", "/local_firmware"}:
            return True
        system = payload.get("system")
        if not isinstance(system, dict):
            return False
        basic = system.get("basicSettings")
        return isinstance(basic, dict) and "apName" in basic

    @staticmethod
    def _response_for(path: str, payload: JsonObject) -> JsonObject:
        if path == "/reboot":
            return {"status": 0}
        if path == "/HardFactory":
            return {"status": 0}
        system = payload.get("system")
        if isinstance(system, dict):
            monitor = system.get("monitor")
            if isinstance(monitor, dict):
                response_monitor: JsonObject = {}
                if "productId" in monitor or "sysVersion" in monitor:
                    response_monitor.update(
                        {"productId": "WAC510", "sysVersion": "V9.9.6.8", "fwType": "Production"}
                    )
                recent = monitor.get("recentCliList")
                if isinstance(recent, dict):
                    limit = next(iter(recent))
                    response_monitor["recentCliList"] = {
                        limit: [
                            {
                                "clientIpAddress": "192.0.2.10",
                                "macAddress": "00:11:22:33:44:55",
                                "hostName": "client",
                                "associatedSsid": "test",
                                "deviceType": "computer",
                                "stationStatus": "Connected",
                                "band": "5GHz",
                            }
                        ]
                    }
                if "radioApStatus" in monitor:
                    response_monitor["radioApStatus"] = {
                        "wlan0": {"numberOfStations": "1"},
                        "wlan1": {"numberOfStations": "2"},
                    }
                if "stats" in monitor:
                    response_monitor["stats"] = monitor["stats"]
                return {"status": 0, "system": {"monitor": response_monitor}}
        return {"status": 0, "echo": payload}


def fake_settings() -> Settings:
    return Settings.from_env(
        {
            "WAC510_URL": "https://192.0.2.1",
            "WAC510_USERNAME": "admin",
            "WAC510_PASSWORD": "secret",
            "WAC510_DOWNLOAD_DIRECTORY": ".",
        }
    )


def make_client(fake_ap: FakeAP) -> WAC510Client:
    return WAC510Client(fake_settings(), transport=httpx.MockTransport(fake_ap.handler))
