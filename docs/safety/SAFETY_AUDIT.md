# kotlin-tor safety audit (consolidated)

**Status:** 0.1.0-SNAPSHOT — **not** C Tor D3 / production anonymity parity, and **not** a completed third-party security review.  
**Scope:** main Kotlin in `:core`, `:proxy`, `:control`, `:android`, `:cli`.  
**Board:** [AUDIT_BOARD.md](AUDIT_BOARD.md) · per-domain: [domains/](domains/) · pass mailboxes: `/tmp/ktor-safety-pass/`.

## Executive summary

Twelve-domain re-audit (2026-08-03) tracked **15 FIXED · 81 OPEN · 11 NEW** domain rows (see board totals). Phase B remediations landed for accept caps, Control non-loopback auth, FakeIp/client map caps, partial-start teardown, and control constant-time compares. The product remains SNAPSHOT: many Critical/High paths are still fail-open (VPN protect, OR CERTS/keypin, bootstrap readiness, KIST python fork, secondary acceptors, wire integer truncate).

## What WAS fixed (verified against current sources)

| Cluster | IDs | Fix |
|---------|-----|-----|
| Accept / in-flight caps | IO-001..004 | `ProxyAcceptLimits` on SOCKS, HTTP CONNECT, DNSPort, Control |
| Loopback Control auth gate | IO-005 (Control), engine | Non-loopback Control requires cookie or hashed password (`isLoopbackHost` / `requireSafeControl`) |
| Partial-start teardown | RET-001, FAI-001, NUL-008 | `teardownPartialStart()`; catch/stop tear down listeners + daemon |
| Engine restart after cancel | CF-002 partial, MEM-007 partial | `ensureScope()` recreates scope + `TorDaemon` (concurrent race still OPEN) |
| Sticky daemon `started` (engine path) | FAI-003 | Engine teardown calls `daemon.stop()` |
| FakeIpDnsCookies | MEM-001 | `maxEntries` + host↔IP prune on expiry/evict |
| TorClient maps | MEM-002 | hopKeys 512 / isolatedCircuits 128 caps |
| VPN protector static leak | MEM-006 | Clear `PlatformNatives.socketProtector` on stop |
| Control secret compares | CRY-007 | COOKIE / SAFECOOKIE / S2K use `constantTimeEquals` |
| DNS recv copy / name parse | BUF-001, BND-007 | Verified safe patterns (keep) |

## What remains Critical / High (not claimed fixed)

| Priority | Canonical | Issue |
|----------|-----------|-------|
| Critical | **RET-002** / FAI-009 | Partial: `OutboundBind` + `PtSocksDialer` fail-closed when protector set; no `protector(-1)` success path. Linux desktop uses SO_MARK protect. Residual: other dial sites / soft paths may remain. |
| Critical | **CF-001** / CRY-009 | OR handshake completes without CERTS; null FP skips identity (keypin soft-fail) |
| Critical | **FAI-002** | `onReady` / `bootstrapped` after any `daemon.start()` return — not circuit `DONE` |
| Critical | **CPU-002** | KIST `LinuxTcpInfo` forks `python3` on the write path |
| Critical | **IO-009** | Secondary AP acceptors (TransPort / UdpGw / Ftp / …) still uncapped |
| Critical | **INT-001** | `u16be`/`u32be` silent truncate on wire lengths |
| Critical | **CF-002** | Engine stop↔start race on `running` (teardown alone insufficient) |
| High | **RET-003** / CRY-010 | Relay `OrAuthenticate.verify` ignored (log-only) |
| High | **RET-006** / TYP-006 | CERTS parse soft-fail → null identity |
| High | **MEM-005** | `Circuit.close` leaks CircuitList / open / PathBias / OR connections |
| High | **CRY-001** / FAI-004 | Control NULL AUTH when cookie+hash both off |
| High | **FAI-005**/006 | SOCKS/HTTP readiness gaps remain; TUN `markBootstrapped` now gated on Tor ready (Android + Linux desktop sessions) |
| High | **BND-001**/003/004 | EXTEND2 / variable-cell / AUTH parse length gaps |
| High | **BUF-003**/005/009 | BEGIN_DIR, decompress bombs, uncapped control lines |
| High | **CF-009** | EXTEND2 async vs DESTROY / CircState race |
| High | **RET-005** / CF-008 | Keypin Result swallow + CHM TOCTOU |
| High | **IO-006**/007 | Cookie file perms; cancel without socket close |
| High | **CRY-002** | Wire ntor/hs-ntor AUTH/MAC still `contentEquals` |
| High | **NUL-002** | `hopKeys[fp]!!` after eviction-capable cache |

Full queue, conflict resolutions (RET↔FAI↔CRY, MEM×IO caps, CF naming, FAI-002 vs Control-gate mislabel), and per-domain tables: **[AUDIT_BOARD.md](AUDIT_BOARD.md)**.

## Conflict resolutions (summary)

1. **RET-001 ≡ FAI-001 ≡ NUL-008** — FIXED teardown; do not reopen.  
2. **RET-002 ≡ FAI-009** — protect fail-closed on primary OR/PT dials when protector installed; Linux full-tunnel attaches SO_MARK protector before bootstrap.  
3. **RET-003 ≡ CRY-010** — AUTH verify ownership under return/crypto.  
4. **CF-001** = OR handshake (not engine teardown); engine race = **CF-002**.  
5. Accept caps **and** ConnLimit; residual uncapped AP = **IO-009**, not a reopen of IO-001..004.  
6. Old “FAIL-002 = Control bind” label was the Control gate — **FAI-002** is bootstrap readiness only.

## Honesty

This audit does **not** claim feature parity with C Tor, anonymity guarantees, or production readiness. SNAPSHOT software. `:demo-android` / `:demo-desktop` demos (loopback or Linux full-tunnel) are **not** a production VPN security boundary. Linux desktop protect is SO_MARK (Tor uplink only), not VpnService. Treat OPEN Critical items as blockers for any anonymity-sensitive deployment.
