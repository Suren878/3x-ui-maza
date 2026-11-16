# MAZA 0.1 — HTTP/2 prototype

MAZA transports WireGuard's UDP packets through an authenticated HTTPS connection. The first
implementation contains a reusable Rust library, `maza-server` for Linux/macOS, a loopback UDP
bridge named `maza-client`, and `maza-keygen`. It is independent of AIRClient's Apple SDK.

```
WireGuard client → 127.0.0.1:51821 → maza-client
                    TLS 1.3 / HTTP/2 CONNECT-UDP
                    maza-server → 127.0.0.1:51820 → WireGuard server
```

The outer connection uses HTTP Extended CONNECT (`:protocol = connect-udp`), DATAGRAM capsules,
and context ID zero as specified by [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) and
[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html). Authentication implements the Ed25519,
empty-realm profile of [RFC 9729](https://www.rfc-editor.org/rfc/rfc9729.html). Each proof is bound
to the actual TLS connection, origin and client key. TLS terminates in `maza-server`; an ordinary
TLS-terminating reverse proxy cannot be put in front of it without implementing trusted exporter
forwarding, which this version does not support. TCP passthrough is possible.

This is an experimental transport, not a claim of undetectability or availability in Russia.
The TLS/HTTP stack is identifiable, Extended CONNECT support is advertised, and traffic lengths
and timings remain observable. Unknown resources and failed authentication receive the same
404 response, but response-time indistinguishability has not been established. HTTP/1.1 and
HTTP/2 serve a small configurable cover page. HTTP/3, traffic shaping, AIRClient integration and
measurements from Russian fixed networks are subsequent stages.

## Build and test

When working in the separate AIRClient checkout, its macOS helper supports:

```sh
./Scripts/maza.sh test --locked
./Scripts/maza.sh clippy --locked --all-targets -- -D warnings
./Scripts/maza.sh build --locked --release --bins
```

Executables are under `.build/maza-target/release/`. `MAZA/Cargo.lock` is separate from the Apple
SDK's lockfile; this workspace uses upstream rustls rather than AIRClient's modified TLS fork.

On Linux, install a Rust toolchain matching `rust-toolchain.toml` and the system C compiler/make
(on Debian/Ubuntu, `build-essential`), then run from this fork's `maza/` directory:

```sh
cargo test --locked
cargo build --locked --release --bins
```

These binaries are in `maza/target/release/`. Build on the server's architecture; Mac binaries
cannot run on Linux. The automated tests use ephemeral certificates and ports on loopback and
require no root, TUN interface, VPN settings or public server. The file-transfer test uses real
WireGuard peers in userspace to upload and download a 1 MiB file through the UDP bridge and
HTTPS relay and compares SHA-256 digests. Other tests exercise flow control, packet boundaries,
peer isolation, reconnects, replay rejection, certificate verification and cover responses.

## Configure the two ends

1. Use an existing WireGuard server on UDP port 51820. Set its host firewall to permit this
   port from loopback only; the kernel WireGuard listener itself normally binds all interfaces.
   MAZA only forwards to the exact loopback endpoint configured on the server and never accepts
   a client-supplied arbitrary destination. WireGuard peers, forwarding, DNS and Internet egress
   remain the WireGuard administrator's configuration.
2. Point a domain you control at the server and obtain a certificate for it. Install the PEM
   certificate chain and TLS private key. This prototype does not obtain or renew certificates.
   For a corporate deployment, use a dedicated hostname such as `vpn.example.com` with a normal
   publicly trusted certificate. A corporate CA also works: supply its PEM certificate through
   `ca_certificate` on each client. Hostname and certificate verification remain mandatory.
   A corporate load balancer must pass TCP through to this service so TLS terminates here.
3. Generate a **separate** authentication key on the client. Do not reuse a WireGuard key:

   ```sh
   mkdir -p MAZA/local
   .build/maza-target/release/maza-keygen --id desktop --out MAZA/local/desktop.pk8
   ```

   The private key is created with mode 0600 on Unix; an existing file is never overwritten.
   Only the public key is printed. Copy that public key into `[[clients]]` in the server config.
   Keep `desktop.pk8` on the client. Add separate key IDs for other computers; at most 64 keys
   are supported per server in this prototype.
   Revoke a computer by removing its `[[clients]]` entry and restarting the server; this closes
   existing tunnels as well. Use `maza-server --watch` for live key/certificate reloads; each accepted update closes existing sessions. There is no employee directory or SSO integration.
4. Copy [examples/server.toml](examples/server.toml) to the server and
   [examples/client.toml](examples/client.toml) to `MAZA/local/client.toml`. Replace the example
   domain, certificate paths and public key. `origin`, key ID, and `wireguard_endpoint` must
   agree at both ends. Relative paths are resolved against the configuration file's directory.
5. Check the files before starting:

   ```sh
   maza-server --config /etc/maza/server.toml --check
   .build/maza-target/release/maza-client --config MAZA/local/client.toml --check
   .build/maza-target/release/maza-client --config MAZA/local/client.toml
   ```

   `--check` validates local configuration, keys and certificate files; it does not test network
   reachability or confirm that the remote server authorizes the key. A network connection starts
   when a local UDP peer sends its first packet.
6. In the WireGuard client, set `Endpoint = 127.0.0.1:51821` and start with a conservative MTU
   such as 1280. Keep the existing WireGuard keys and peer addresses. For the first test, route
   only the private WireGuard subnet through this interface and test the server's private IP.

For a full-tunnel OS WireGuard configuration, the MAZA HTTPS server's actual IP must have a route
through the physical gateway **outside** WireGuard. Otherwise MAZA's TCP connection can route
back into its own tunnel. Use `server_address` with that explicit route and maintain it when the
physical network changes. This standalone bridge does not install routes, a kill switch, DNS
settings or a TUN device. AIRClient's future integration must bind its outer sockets to the
physical interface and test DNS/IPv6 leak prevention separately.

## Linux service

The [systemd unit](deploy/maza-server.service) runs as an unprivileged `maza` user with only the
capability needed to bind TCP/443. Install the Linux binary and your completed configuration:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin maza
sudo install -d -m 0750 -o root -g maza /etc/maza
sudo install -m 0755 target/release/maza-server /usr/local/bin/maza-server
sudo install -m 0640 -o root -g maza /path/to/server.toml /etc/maza/server.toml
sudo install -m 0640 -o root -g maza /path/to/fullchain.pem /etc/maza/fullchain.pem
sudo install -m 0640 -o root -g maza /path/to/tls-key.pem /etc/maza/tls-key.pem
sudo install -m 0644 deploy/maza-server.service /etc/systemd/system/maza-server.service
sudo -u maza /usr/local/bin/maza-server --config /etc/maza/server.toml --check
sudo systemctl daemon-reload
sudo systemctl enable --now maza-server
sudo systemctl status maza-server
```

Create the user only once. TCP/443 must be available and reachable. Check the service log with
`journalctl -u maza-server`; payloads and authentication values are not logged. Restart the
service after changing certificates or authorized keys, or run it with `--watch`. Clients reconnect on subsequent local
traffic after an interrupted connection; in-flight UDP packets can be lost during recovery.

Limits are intentional: 128 incoming connections and 64 UDP tunnels by default, eight HTTP/2
streams per connection, 16 local UDP peers per client, bounded 16-packet queues, 10-second
connection timeouts, 15-second blocked-write timeouts and a configurable idle timeout.
The server returns replies only from its connected UDP target. HTTP/2 imposes TCP head-of-line
blocking; its performance under packet loss still needs external measurement.

Before treating this as deployable for everyday use, run the Linux tests on the actual target,
check the TLS certificate and outer routing, then compare long transfers against AWG and REALITY
from Russian fixed networks. The local tests do not establish resistance to TSPU classification.

## 3x-ui integration

The [panel module](../MAZA.md) adds authenticated client creation,
QR/link and ZIP exports, and revocation to the [3x-ui MAZA fork](https://github.com/Suren878/3x-ui-maza).
The relay accepts Go-generated PKCS#8 v1 keys and can reload a deny-all configuration
after the last client is removed. AIRClient support remains a separate integration.
