# Architecture

See repository README for module map.

**Completeness truth:** [`docs/CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md)  
(feature demo board only: [`PARITY_GAPS.md`](../PARITY_GAPS.md))

```
App / CLI / Android / demos
    │
    ├─ :demo-android / :demo-desktop  — Material 3 shells (extras)
    │     └─ :demo-common → TorDaemon + proxies
    │           · Android VPN: VpnService + OnionTunnel
    │           · Linux desktop VPN: TUN + SO_MARK (Tor uplink only) + OnionTunnel
    ├─ :cli                           — headless daemon / debug
    ├─ control-spec (:control)        — subset vs feature/control/*.c (mostly D2)
    ├─ SOCKS5H (:proxy)               — live client path; not full C Tor client/
    └─ TorDaemon (:core)
          ├─ TorClient (bootstrap, circuits, streams) — partial vs core/or + nodelist
          ├─ OnionServiceManager — hs_client/hs_service hot paths; many hs_*.c still D1/D2
          ├─ RelayService — ORPort/exit/dir partial (not full feature/relay)
          ├─ OnionTunnel / TunIpStack — userspace TUN NI (pure Kotlin)
          └─ PtManager — external PTs + ExtOR; transports.c thinner
```

## Linux full-tunnel (desktop demo)

1. Snapshot physical default route; install fwmark policy table for Tor uplink.
2. Attach `LinuxSocketMarkProtector` → `PlatformNatives.socketProtector` (OR/PT dials only).
3. Bootstrap `TorDaemon` (marked sockets use physical NIC).
4. Open `/dev/net/tun`, configure address, install default via TUN.
5. Start `OnionTunnel` only after Tor bootstrapped + protector attached.
6. Teardown restores routes and clears protector.

Requires `CAP_NET_ADMIN` and `ip` (iproute2). Fail-closed if missing.
## Honesty

- Status remains **0.1.0-SNAPSHOT**.
- Scanner: **L1 D3≈213 · D2=0 · N/A≈166**; global still **majority D2** across L2–L4 (~1916 D2). Not full C Tor parity.
- ~197 main Kotlin sources vs ~383 C Tor product `.c` files (ex test/ext).
- Dozens of Kotlin units self-label `lite`; inventory grades most mirrors **D2**, not done.
- Relay ORPort, directory authority, circpad, KIST, and full `or_options_t` semantics are **partial**.
- Phase OM: pure-Kotlin `OnionTunnel` NI + OnionVPN `TorEngine.KOTLIN_TOR` on HEV_SOCKS (product surface; not inventory D3).

## Current live milestones (demo paths — not module completion)

1. Consensus + descriptors (dir authorities)
2. OR TLS + CERTS/NETINFO + CREATE2/ntor (+ ntor-v3 / CGO live EXTEND)
3. Exit BEGIN/DATA + SOCKS5H
4. HS v3 client + host hot path (descriptor, INTRODUCE/REND, publish)
5. Control SAFECOOKIE / password / SETCONF subset
6. ExtORPort + PT process manager subset
7. DNSSEC validating stub (`DNSSECMode=validate`) — TCP DNS via Tor exit to a recursive, local RRSIG/DNSKEY/DS validation to IANA root anchors (not DNSCrypt; fail closed; TUN fake-IP unchanged)
8. DNS resolve isolation — each `TorClient.resolve` / DNSPort query gets a dedicated circuit (not shared with SOCKS); torn down after the request

Next work must pick `row_id` from [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md).
