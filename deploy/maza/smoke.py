#!/usr/bin/env python3
"""Exercise an isolated panel and relay; credentials never go to stdout.

The relay container must mount export-dir at /probe and its test CA at
/cert/fullchain.pem. Do not point this test at a panel with real clients.
"""
import argparse
import base64
import http.cookiejar
import io
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--url", required=True)
p.add_argument("--credentials", type=Path, required=True)
p.add_argument("--export-dir", type=Path, required=True)
p.add_argument("--container", required=True)
args = p.parse_args()
base = args.url.rstrip("/")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
token = ""


def request(path, data=None, *, auth=True, csrf=True):
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if csrf and token:
        headers["X-CSRF-Token"] = token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
    try:
        response = (opener.open(req, timeout=30) if auth else urllib.request.urlopen(req, timeout=10))
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def api(path, data=None):
    code, _, body = request(path, data)
    value = json.loads(body)
    if code != 200 or not value.get("success"):
        raise RuntimeError(f"API operation failed: {path}: {value.get('msg', code)}")
    return value.get("obj")


route = "/panel/maza/api/clients"
assert request(route, auth=False)[0] == 401, "anonymous list accepted"
token = api("/csrf-token")
api("/login", json.loads(args.credentials.read_text()))
token = api("/csrf-token")
assert request(route, {"name": "csrf-probe"}, csrf=False)[0] == 403
for _ in range(40):
    status = api(route)
    if not status["pending"]:
        break
    time.sleep(0.5)
else:
    raise RuntimeError("relay configuration did not become ready")
assert not status["clients"], "smoke test requires an empty isolated panel"

api(route, {"name": "Smoke A"})
api(route, {"name": "Smoke B"})
clients = api(route)["clients"]
assert len(clients) == 2 and clients[0]["address"] != clients[1]["address"]
assert all(set(c) == {"id", "name", "address", "created"} for c in clients)
client = next(c for c in clients if c["name"] == "Smoke A")
path = route + "/" + client["id"]
assert request(path + "/share", auth=False)[0] == 401
link = api(path + "/share")["link"]
assert link.startswith("maza://")
encoded = link.removeprefix("maza://")
profile = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
assert profile["version"] == 1 and profile["origin"] == status["origin"]
code, headers, data = request(path + "/bundle")
assert code == 200 and headers["Cache-Control"] == "no-store"
args.export_dir.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    assert set(z.namelist()) == {"client.toml", "client.pk8", "wireguard.conf", "profile.json", "profile.maza", "README.txt"}
    for name in ["client.toml", "client.pk8", "wireguard.conf"]:
        target = args.export_dir / name
        target.write_bytes(z.read(name))
        target.chmod(0o600)
        os.chown(target, 10002, 10002)
with (args.export_dir / "client.toml").open("a") as f:
    f.write('\nca_certificate = "/cert/fullchain.pem"\n')

probe = ["docker", "exec", args.container, "/usr/local/bin/maza-probe", "--config", "/probe/client.toml", "--wireguard", "/probe/wireguard.conf"]
for _ in range(10):
    result = subprocess.run(probe, capture_output=True, timeout=35)
    if result.returncode == 0:
        break
    time.sleep(1)
else:
    raise RuntimeError("real WireGuard handshake failed: " + result.stderr.decode(errors="replace")[:600])
print("PASS: login, CSRF, client isolation, private exports, TLS + MAZA + WireGuard handshake")
api(path + "/delete", {})
time.sleep(2)
result = subprocess.run(probe, capture_output=True, timeout=35)
assert result.returncode != 0 and b"HTTP 404" in result.stderr, "revoked profile still accepted"
for c in api(route)["clients"]:
    api(route + "/" + c["id"] + "/delete", {})
assert not api(route)["clients"]
print("PASS: revocation rejected the old credentials; all test clients removed")
