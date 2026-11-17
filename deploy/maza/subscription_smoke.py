#!/usr/bin/env python3
"""Check subscriptions using normal panel login; never log bearer URLs or keys.

Default mode only reads existing clients. --isolated creates two temporary MAZA
clients and requires an empty test instance. Optional output is private and can
be consumed by AIRClient's production SubscriptionLoader verification tool.
"""
import argparse
import base64
import http.cookiejar
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--credentials', required=True)
p.add_argument('--url')
p.add_argument('--output')
p.add_argument('--isolated', action='store_true')
a = p.parse_args()
os.umask(0o077)
credentials = json.loads(Path(a.credentials).read_text())
base = (a.url or ('http://127.0.0.1:2053/' + credentials['base_path'].strip('/'))).rstrip('/')
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ''


def api(path, data=None):
    headers = {'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': csrf}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(base + path, headers=headers,
                                 data=None if data is None else json.dumps(data).encode())
    with opener.open(req, timeout=30) as response:
        payload = json.load(response)
    assert payload.get('success'), 'panel API failed at ' + path.split('/clients/')[0]
    return payload.get('obj')


def ready():
    for _ in range(80):
        status = api('/panel/maza/api/clients')
        if not status['pending']:
            return status['clients']
        time.sleep(.25)
    raise RuntimeError('MAZA reconciliation timed out')


def fetch(url, ua='AIRClient/0.3.3'):
    # No panel cookies are used on the public subscription endpoint.
    request = urllib.request.Request(url, headers={'User-Agent': ua, 'Accept': 'text/plain'})
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        return error.code, [], {}
    with response:
        raw = response.read(2 * 1024 * 1024)
        try:
            body = base64.b64decode(raw, validate=True).decode()
        except (ValueError, UnicodeError):
            body = raw.decode()
        return response.status, body.strip().splitlines(), response.headers


csrf = api('/csrf-token')
api('/login', {key: credentials[key] for key in ('username', 'password')})
csrf = api('/csrf-token')
clients = ready()
owned = []
fixtures = []
try:
    if a.isolated:
        assert not clients, '--isolated requires empty MAZA instance'
        for name in ('subscription-smoke-a', 'subscription-smoke-b'):
            api('/panel/maza/api/clients', {'name': name, 'email': name})
            clients = ready()
            owned = clients
    assert clients, 'no MAZA client available to verify'
    for client in clients:
        path = '/panel/maza/api/clients/' + client['id']
        direct = api(path + '/share')['link']
        url = api(path + '/subscription')['link']
        assert url.startswith(('https://', 'http://127.0.0.1:'))
        for ua in ('AIRClient/0.3.3', 'sing-box/1.12 AIR Client'):
            status, links, headers = fetch(url, ua)
            assert status == 200 and links == [direct], 'subscription differs from native export'
            assert 'no-store' in headers.get('Cache-Control', '')
            assert 'subscription-userinfo' in headers and 'profile-update-interval' in headers
        native = json.loads(base64.urlsafe_b64decode(direct[7:] + '=' * (-len(direct[7:]) % 4)))
        assert native['version'] == 2 and len(native['maza']) == 21
        assert api(path + '/subscription')['link'] == url, 'subscription URL changed on reload'
        bad_url = url.rsplit('/', 1)[0] + '/' + secrets.token_urlsafe(24)
        assert fetch(bad_url)[0] == 404, 'unknown subscription was accepted'
        fixtures.append({'url': url, 'links': [direct]})
    # Existing conventional subscriptions must still return importable links.
    if not a.isolated:
        defaults = api('/panel/api/setting/defaultSettings', {})
        rows = api('/panel/api/clients/list')
        maza_emails = {c['email'] for c in clients}
        for row in rows:
            if row['email'] in maza_emails or not row.get('subId'):
                continue
            url = defaults['subURI'] + row['subId']
            status, links, _ = fetch(url)
            assert status == 200 and links, 'ordinary subscription failed'
            assert all(link.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'socks://', 'hy2://', 'hysteria2://', 'tuic://', 'wireguard://', 'maza://')) for link in links)
            fixtures.append({'url': url, 'links': links})
    if a.output:
        output = Path(a.output)
        output.write_text(json.dumps(fixtures))
        output.chmod(0o600)
    print(f'PASS: {len(clients)} native MAZA subscriptions; peer isolation, reload, legacy/new AIRClient, headers and unknown token')
    if not a.isolated:
        print(f'PASS: {len(fixtures) - len(clients)} ordinary subscriptions')
finally:
    if a.isolated:
        for client in owned:
            api('/panel/maza/api/clients/' + client['id'] + '/delete', {})
            ready()
        for fixture in fixtures:
            assert not any(link.startswith('maza://') for link in fetch(fixture['url'])[1]), 'revoked native key still published'
        assert not ready(), 'temporary clients remain'
        print('PASS: revocation and isolated fixture cleanup')
