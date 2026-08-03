# kotlin-tor safety audit (consolidated)

**Status:** 0.1.0-SNAPSHOT — **not** a C Tor D3 / production anonymity audit.  
**Scope:** main Kotlin in `:core`, `:proxy`, `:control`, `:android`, `:cli`.  
**Board:** [AUDIT_BOARD.md](AUDIT_BOARD.md) · per-domain: [domains/](domains/).

## Executive summary

Twelve-domain communicating audit (memory, io, cpu, type, return, bounds, crypto, buffer, null, integer, failure, controlflow) produced a shared board. Router-path Critical/High remediations prioritized: **unbounded proxy accept**, **partial-start without teardown**, **non-loopback Control + NULL auth**, **unbounded client maps**, and **control auth compare timing**. Additional Critical/High outside that fix order (OR handshake CERTS skip, protect fail-open, variable-cell length DoS, HS FSM races, integer wire overflow) are listed under **Deferred**.

## Critical / High fixed this pass

| ID | Finding | Fix |
|----|---------|-----|
| IO-001 / FAIL-004 | SOCKS accept unbounded | `Semaphore` via `maxConcurrent` (`ProxyAcceptLimits.DEFAULT_TCP`) |
| IO-002 | HTTP CONNECT accept unbounded | same |
| IO-003 | DNSPort UDP in-flight flood | in-flight semaphore |
| IO-004 | ControlServer accept unbounded | session semaphore (32) |
| IO-005 / CRY-002 / FAIL-002 | Non-loopback Control without auth | `require` cookie or hashed password; `ListenSpec.isLoopbackHost()` |
| RET-001 / FAIL-001 / NUL-003 | Engine partial-start | `teardownPartialStart()`; recreate scope/`TorDaemon` after stop |
| MEM-001 | FakeIpDnsCookies unbounded | `maxEntries` + host-map prune on expiry/evict |
| MEM-002 | hopKeys / isolatedCircuits | caps 512 / 128 with LRU-ish eviction |
| CRY-001 (control) | `contentEquals` on cookie/S2K | `constantTimeEquals` |
| CF-001 (engine) | stop kills restart | recreate scope + daemon on next start |

## Medium / Low noted

| Topic | Disposition |
|-------|-------------|
| CLI `safeSocks=false` default | Deferred; router/demo keep true |
| CreateFast legacy | Document only |
| `hopKeys!!` API | Deferred reshape |
| ConnectionTable soft growth | Mitigated by accept caps |
| UnparseableDump size | Deferred |
| ntor AUTH still `contentEquals` | Deferred (wire path) |

## Conflict resolutions → fix order (applied)

1. Accept / in-flight caps → fail-closed close/drop excess.
2. Partial-start teardown → stop siblings + daemon; recreate scope for restart.
3. Bind safety → loopback helper; non-loopback Control requires auth; warn on non-loopback Socks/HTTP/DNS.
4. Map caps → FakeIp + TorClient tables.
5. Crypto compares → constant-time for control secrets only this pass.

## Remediations landed (code)

- `proxy`: `ProxyAcceptLimits`, gated `Socks5Server` / `HttpConnectProxy` / `DnsPortServer`; `ProxyAcceptCapTest`
- `control`: gated `ControlServer` + non-loopback auth require + constant-time cookie/SAFECOOKIE
- `android`: `KotlinTorEngine` teardown / `routerDefaultConfig` / bind checks
- `core`: `FakeIpDnsCookies` caps, `TorClient` map caps, `constantTimeEquals`, `ListenSpec.isLoopbackHost`
- `:demo-router` Material XML app (INTERNET only, no VpnService)

## Deferred (auditor Critical/High outside Phase B order)

Documented on the board; **not** claimed fixed:

- OR handshake completing without CERTS when `expectedIdentityHex` set (controlflow)
- `protectSocket` / VPN protect fail-open (return) — VPN path
- Variable-length OR cell `len` large alloc (bounds)
- EXTEND2 / CREATE payload length OOB edges (bounds)
- Relay AUTHENTICATE ignored failure (return)
- HS intro FSM / replay TOCTOU (controlflow)
- Wire `u16be`/`u32be` overflow encode (integer)
- Bootstrap/`onReady` before circuit ready semantics (failure) — still bootstrap-dependent
- Dirauth keypin silent conflicts (return)

## Honesty

This audit does **not** claim feature parity with C Tor, anonymity guarantees, or a completed third-party security review. SNAPSHOT software. `:demo-router` is a loopback proxy demo only.
