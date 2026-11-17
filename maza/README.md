# MAZA native core

`core-go` is the pinned local MIT-licensed WireGuard/AWG 3.1 fork described in
`UPSTREAM.json`. The panel embeds it through the root module's `replace` directive.
`device/maza_profile.go` supplies mandatory protection parameters; it does not
replace Noise or the authenticated-encryption primitives. The core is AWG 3.1
wire-compatible. See ../MAZA.md for deployment and profile export.

`tests/peer` is a loopback-only interoperability test fixture, not a production
relay. It is used by AIRClient's `Scripts/test-maza-client.sh`.
