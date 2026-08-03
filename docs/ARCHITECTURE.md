# Architecture

See repository README for module map.

**Completeness truth:** [`docs/CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md)  
(feature demo board only: [`PARITY_GAPS.md`](../PARITY_GAPS.md))

```
App / CLI / Android
    │
    ├─ control-spec (:control)     — subset vs feature/control/*.c (mostly D2)
    ├─ SOCKS5H (:proxy)            — live client path; not full C Tor client/
    └─ TorDaemon (:core)
          ├─ TorClient (bootstrap, circuits, streams) — partial vs core/or + nodelist
          ├─ OnionServiceManager — hs_client/hs_service hot paths; many hs_*.c still D1/D2
          ├─ RelayService — ORPort/exit/dir partial (not full feature/relay)
          └─ PtManager — external PTs + ExtOR; transports.c thinner
```

## Honesty

- Status remains **0.1.0-SNAPSHOT**.
- Scanner: **D0=0 · D1≈0 · majority D2 · ~11 D3 · N/A≈203**.
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

Next work must pick `row_id` from [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md).
