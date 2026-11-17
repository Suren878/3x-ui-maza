# Native MAZA subscriptions

Panel `3.11.0-maza.4` exports a native `maza://` v2 link in each client's standard
subscription. Its normalized client record owns the subscription ID. Reconciliation
fills missing IDs using the normal client API, preserving existing IDs and keys.
The public subscription endpoint only exports peers already matched by the bearer
subscription ID; admin exports remain behind login and owner checks.

The MAZA page has a **Подписка** button with the URL and QR. The ordinary Client
Information dialog uses the same standard feed. Use AIRClient `0.3.3 (16)` or later.
Xray JSON and Clash YAML deliberately omit MAZA rather than emitting incomplete
WireGuard/AWG settings. The standard route recognizes both new and older AIRClient
User-Agents and always returns share links, even with format autodetection enabled.

## HTTPS publication

Publish container port 2096 only on loopback, for example
`127.0.0.1:12096:2096/tcp`. Add an nginx location for the configured `subPath`,
proxying to `http://127.0.0.1:12096` with the original URI and Host. Use the domain's
valid TLS certificate and disable access logging/caching for bearer URLs. Set
`subURI` to the complete public HTTPS prefix including the trailing slash. The
panel management route/port alone does not publish subscriptions.

Keep existing subscription IDs/paths. Do not put credentials or exported profiles
in Compose, Docker images, Git, build logs or screenshots. Keep a consistent SQLite
backup and MAZA state before deployment, test restore off-host, and retain the
previous runtime image for rollback without restoring an older client database.

## Verification

`subscription_smoke.py` authenticates using a supplied operator credentials file.
Without `--isolated` it only reads existing clients and checks their public feeds.
`--isolated` requires an empty test instance, creates two test peers, checks feed
isolation, native export equality, headers, reloads, legacy/new AIRClient routing,
unknown IDs and revocation, and removes the peers afterwards. Optional `--output`
is a mode-0600 manifest for AIRClient's `Tests/LiveSubscriptionCheck.swift`; never
publish this manifest. The Swift checker downloads real HTTPS feeds using the
production loader and parser, repeats the update, and emits private core configs
for `air_core_validate`.
