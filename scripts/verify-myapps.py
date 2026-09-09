#!/usr/bin/env python3
import base64
import json
import ssl
import urllib.request

ctx = ssl._create_unverified_context()

def read_json(url, auth=None):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if auth:
        raw = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {raw}")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
        return response.status, json.loads(response.read().decode())

def names(payload):
    items = payload if isinstance(payload, list) else payload.get("applications") or payload.get("items") or payload.get("Resources") or payload.get("results") or []
    return {str(x.get("name") or x.get("displayName") or x.get("applicationName")) for x in items if isinstance(x, dict)}

with urllib.request.urlopen("http://localhost:3000/myapps/", timeout=10) as response:
    html = response.read().decode()
    if response.status != 200:
        raise AssertionError(f"/myapps/ returned HTTP {response.status}")
    if "My applications" not in html:
        title = ""
        if "<title>" in html and "</title>" in html:
            title = html.split("<title>", 1)[1].split("</title>", 1)[0]
        raise AssertionError(
            "/myapps/ returned HTTP 200 but not the dedicated My Apps HTML. "
            f"Returned title={title!r}, first 180 chars={html[:180]!r}"
        )
print("[pass] separate My Apps UI is served at /myapps/")

_, config = read_json("http://localhost:4000/api/config")
client = config.get("clients", {}).get("appPortal", {})
assert client.get("clientId"), "clients.appPortal.clientId missing"
assert client.get("redirectUri") == "http://localhost:3000/myapps/callback.html"
print("[pass] dedicated Application Portal OIDC client is published")

with urllib.request.urlopen("https://localhost:9443/myaccount", context=ctx, timeout=10) as response:
    assert response.status in (200, 302)
print("[pass] native WSO2 My Account remains available")

expected = {
    ("alice", "Alice@123"): {"Portal Corporativo", "Finance Workspace"},
    ("carol", "Carol@123"): {"Portal Corporativo", "Security Operations"},
    ("bob", "Bob@1234"): set(),
}
demo_names = {"Portal Corporativo", "Finance Workspace", "Security Operations"}
for creds, wanted in expected.items():
    _, payload = read_json("https://localhost:9443/api/users/v1/me/applications", creds)
    actual = names(payload) & demo_names
    assert actual == wanted, f"{creds[0]} catalog expected {sorted(wanted)}, got {sorted(actual)}"
    print(f"[pass] {creds[0]} native WSO2 catalog -> {sorted(actual)}")

print("[pass] discoverability remains sourced from WSO2")
print("[info] My Apps:    http://localhost:3000/myapps/")
print("[info] My Account: https://localhost:9443/myaccount")
