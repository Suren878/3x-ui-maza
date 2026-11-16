# MAZA module for 3x-ui 3.11.0

The maintained panel fork is [Suren878/3x-ui-maza](https://github.com/Suren878/3x-ui-maza).
The first deployment branch is `codex/maza-integration`, based on upstream commit
`5297fd3c8495d80fab97ae511553fa545c69e913`. This directory contains the reproducible
overlay used to prepare that branch. It does not change Xray's protocol registry.

The MAZA page uses the panel's existing session and CSRF middleware. It creates an
independent Ed25519 authentication key and WireGuard keypair per client, allocates
an address from `10.78.0.0/24`, and manages a loopback-only WireGuard inbound named
`maza-managed` on UDP 51829. Manage these clients from the MAZA page; ordinary
WireGuard share links from the native inbound are not MAZA profiles.

The page supports create, list, QR/link export, ZIP download and revoke (64 clients
per server). Secrets appear only in an explicitly requested authenticated export;
the list never includes private keys. QR generation happens inside the browser.
Responses containing profiles are `Cache-Control: no-store`. ZIP entries and state
files are mode 0600. The state file lives outside Git and container images.

## Configuration

Set `MAZA_ORIGIN=https://vpn.example.com:9443` on the panel. A domain and a matching
trusted certificate are required. `MAZA_SERVER_ADDRESS=192.0.2.1:9443` is optional:
it pins the connection address while retaining the domain for TLS verification.
Without it, the client resolves the domain normally. Neither the source nor the
build contains a deployment-specific domain or IP.

The panel writes its private desired state to `<XUI_DB_FOLDER>/maza/state.json` and
the relay's public allowlist to `maza/relay/server.toml`. Mount **only** the relay
subdirectory read-only into `maza-server` at `/config`, and the deployment's TLS
files at `/cert/fullchain.pem` and `/cert/privkey.pem`. The relay shares the panel's
network namespace (`network_mode: service:panel`) so it can reach WireGuard on
loopback. Both run as the same unprivileged UID, without capabilities or host devices.

Start the relay with `--config /config/server.toml --watch`. It watches keys and
certificates once per second, validates replacements, and closes previous sessions
on a valid change. Invalid files retain the last valid configuration. Empty client
lists deny all tunnel access. Client changes therefore briefly interrupt existing
MAZA sessions. Failed backend changes remain pending and retry every three seconds.
Revocation publishes the transport deny decision before retrying backend cleanup.

TLS must terminate at MAZA: use nginx **TCP stream passthrough**, not HTTP proxying.
A separate public port such as 9443 can coexist with websites already using 443.
Using 443 on a shared IP requires a separately planned SNI passthrough arrangement.

## Build

In the AIRClient checkout:

```sh
git clone https://github.com/Suren878/3x-ui-maza.git MAZA/local/3x-ui
git -C MAZA/local/3x-ui checkout 5297fd3c8495d80fab97ae511553fa545c69e913
python3 MAZA/integrations/3x-ui/apply.py MAZA/local/3x-ui
docker build -f MAZA/integrations/3x-ui/Dockerfile.panel -t local/3x-ui-maza:3.11.0-maza1 MAZA/local/3x-ui
docker build -f MAZA/deploy/Dockerfile -t local/maza-relay:0.1.0-panel1 MAZA
```

In the panel fork, the Rust workspace is `maza/` and the panel Dockerfile is
`deploy/maza/Dockerfile.panel`. Build from the fork root:

```sh
docker build -f deploy/maza/Dockerfile.panel -t local/3x-ui-maza:3.11.0-maza1 .
docker build -f maza/deploy/Dockerfile -t local/maza-relay:0.1.0-panel1 maza
```

The panel build runs TypeScript checking, frontend production compilation and the
MAZA provisioning/export/revocation tests. The relay build runs the Rust tests on
Linux before compiling the release executables. Back up the panel database and
MAZA state before replacing a panel image; preserve the original image and Compose
configuration for rollback. For an upstream panel upgrade, first migrate a separate backup with outbound traffic disabled and verify its integrity. An older panel must be rolled back together with its pre-upgrade database.

## Client profile v1

`maza://` followed by unpadded base64url UTF-8 JSON. Fields: `version` (1), `name`,
`origin`, optional `server_address`, `wireguard_endpoint` (the fixed server loopback
target), `key_id`, `auth_private_key` (base64url Ed25519 PKCS#8 DER), and `wireguard`
with `private_key`, `public_key` (server), `address`, `dns`, `allowed_ips`, `mtu`,
and `keepalive`. Treat the whole link as a secret. Do not put it in analytics or logs.

ZIP exports include `client.toml`, `client.pk8`, `wireguard.conf`, the profile in
JSON/link form and usage notes. Run `maza-client --config client.toml`, then use
WireGuard with endpoint `127.0.0.1:51821`. A full tunnel must exclude the outer MAZA
server IP from its routes; the standalone bridge does not install routing or DNS.

AIRClient import/transport integration is not included in this panel module yet.
Standard WireGuard clients cannot import a `maza://` QR directly. No claim of
undetectability or resistance to a particular network's DPI is made by these tests.
