# MAZA native for 3x-ui 3.11.0

The panel embeds the locally vendored WireGuard/AWG 3.1 Go core in `maza/core-go`.
It creates a managed native UDP inbound (`maza-managed`) on port 9443, with a random
header-protection key and required padding/timing parameters. There is no separate
MAZA container, TLS transport, bridge executable or Xray protocol-registry patch.
Existing userspace AWG routing integrates with the panel's normal Xray outbound.

Panel `3.11.0-maza.5` prioritizes data classification when random trailers are
enabled, matching the Rust receiver. Previously, ciphertext at a different S-offset
could accidentally match a handshake H-range and cause a valid data packet to be
discarded. New inbounds use one random 12–31-byte prefix length for S1–S4, making
the disjoint type ranges unambiguous. Existing v2 profiles, keys and parameters
remain valid; this update does not rotate a running inbound's parameters.

Set `MAZA_ENDPOINT=vpn.example.com:9443` on the panel and publish container UDP 9443
on that endpoint. Keep the web panel behind its authenticated HTTPS reverse proxy.
Runtime remains unprivileged, read-only, capability-free, with its own database
volume and the existing project's network isolation. No TUN device is required.

Create the MAZA inbound from the inbound dialog, then create a client in the normal
client dialog or MAZA page. QR, link and ZIP exports are available. Import the link
or `profile.json` into AIRClient 0.3.2 (15)+. Profiles are v2; ordinary WireGuard QR
codes are not offered for the managed inbound. Its native settings are managed by
MAZA rather than the generic AWG editor. Disable/revoke clients on the MAZA page.
Use one client profile per device; sharing a live profile between devices makes
the peer roam between their endpoints and can interrupt both connections.

The session and CSRF middleware protect all MAZA API operations. Exports are
`Cache-Control: no-store`; listings omit keys. State and ZIP entries use mode 0600.
Desired changes are saved before reconciliation; failed backend changes remain
pending, are retried, and block exports until applied. The interface supports up
to 64 managed clients. Header protection parameters are shared by clients of this
inbound; a leaked profile must be treated as a compromise of that shared disguise.
Individual WireGuard peer keys still control tunnel authentication.

Client creation returns HTTP 202 after durable storage. The existing reconciler
then applies it, and exports stay unavailable while `pending` is true. The UI
waits for readiness and recovers a lost response by reading the client list,
without repeating the creation request. This matters when the administrator
opens the panel through this VPN: updating Xray's authenticated SOCKS account
list currently restarts Xray and may briefly interrupt that connection.

## Build and validate

```sh
docker build -f deploy/maza/Dockerfile.panel -t local/3x-ui-maza:native-v2 .
go test ./internal/web/service -run '^TestMaza' -count=1
go test ./internal/sub -run '^TestMazaNoWireguardLink$' -count=1
(cd maza/core-go && go test ./device -run '^TestMaza' -count=1)
```

Back up the database, `maza/state.json` and Compose configuration off-host before
upgrading. Test a copy in a separate isolated project and keep the previous image
and state together for rollback. An empty v1 prototype inbound is migrated to v2;
migration refuses existing v1 clients. Remove the obsolete relay and its published
TCP port after successful native validation. Preserve unrelated inbounds and the
panel HTTPS configuration. Database schema remains 3.11.0.

## Profile v2

`maza://` + unpadded base64url JSON: `version: 2`, `name`, `server`, `port`, `maza`
(the required string parameter map), `wireguard` (`private_key`, `public_key`,
`address`, `dns`, `allowed_ips`, `mtu: 1280`, `keepalive`). ZIP contains only
`profile.maza`, `profile.json`, `README.txt`. Never log the export.

This is a WireGuard-derived AWG 3.1 profile, not new cryptography or a guarantee
against DPI. IP blocks, statistical classifiers and generic UDP restrictions can
still affect it; real network measurements are required.
