# Domain: return

Ignored `Boolean`/`Result`, silent `runCatching`, and partial-success APIs in main sources (`core` / `proxy` / `control` / `android`). Cap ~8 Critical/High.

**Pass:** re-verify 2026-08-03 · mailbox `/tmp/ktor-safety-pass` (README only; no peer domain drops at audit time).

## Status rollup

| ID | Risk | Status | One-liner |
|----|------|--------|-----------|
| RET-001 | Critical | **FIXED** | `teardownPartialStart()` stops listeners + daemon; catch/stop use it |
| RET-002 | Critical | **FIXED** | Fail-closed OR/PT dial when `protectSocket` returns `false` |
| RET-003 | High | **OPEN** | `OrAuthenticate.verify` Boolean ignored |
| RET-004 | High | **OPEN** | Relay TLS `startHandshake` in silent `runCatching` |
| RET-005 | High | **OPEN** | `Keypin.checkAndAdd` Result swallowed |
| RET-006 | High | **OPEN** | CERTS parse soft-fails → null identity |
| RET-007 | High | **OPEN** | `ADD_ONION` 250 OK before publish; failure only `System.err` |
| RET-008 | Medium | **OPEN** | OnionTunnel refresh/dormant silent `runCatching` |

**Top 3 open:** RET-003, RET-006, RET-004

**NEW Critical/High this pass:** none (cap held; residual notes under RET-001 only).

---

### [RET-001] `startWithPorts` partial success: sibling teardown — **FIXED**
- **Track**: return
- **Status**: FIXED (Phase B / SAFETY_AUDIT)
- **Evidence (current)**:
  - `android/.../KotlinTorEngine.kt:147-155` — `catch` calls `teardownPartialStart()` then clears `running` / `bootstrapped` before `onError`
  - `:159-170` — `stop()` also calls `teardownPartialStart()`, clears `vpnTunnel` / `socketProtector` / `PlatformNatives.socketProtector`, then `scope.cancel()`
  - `:192-205` — `teardownPartialStart()` stops `socks`, all `roleSocks`, `dnsPort`, `httpConnect`, `control` (null refs), then `daemon.stop()`
  - `:184-188` — `ensureScope()` recreates `CoroutineScope` + `TorDaemon` after cancel (restart path)
- **Completeness check**: Listeners + daemon + field nulling **complete** for start-failure and stop. Residual (not re-opened as Critical):
  - `bootstrapped.set(true)` still at `:114` immediately after `daemon.start()`, before ports bind — readiness semantics remain FAIL-002 / FAIL-005, not missing teardown
  - Partial-start catch does **not** clear static `PlatformNatives.socketProtector` (intentional for VPN re-attach; `stop()` does clear — MEM-006)
  - `TorDaemon.stop()` no-ops if `!started.get()` (`TorDaemon.kt:329-330`); safe given start order (`daemon.start()` before listeners)
- **Related**: FAIL-001, NUL-003, CF-001/002, MEM-006/007, IO-007/008

### [RET-002] `protectSocket` `false` ignored on OR / PT dial — **FIXED**
- **Track**: return
- **Status**: FIXED
- **Evidence**: `NetworkPolicy.connectDirect` / `PtSocksDialer.connect` — when protector set and `protectSocket` returns `false`, close socket and throw (fail-closed). Do not regress.
- **Related**: FAI-009 FIXED (alias), MEM-006, NUL-004

### [RET-003] `OrAuthenticate.verify` Boolean ignored — **OPEN**
- **Track**: return
- **Status**: OPEN
- **Evidence**: `core/.../relay/RelayService.kt:449-457` — `val ok = OrAuthenticate.verify(...)` only `println`; parse failures logged; neither closes the link nor rejects subsequent CREATE2 when `ok==false`.
- **Risk**: High (relay accepts unauthenticated OR peer after AUTHENTICATE)
- **Fix**: If `!ok` (or parse fails), destroy connection / refuse further cells. Do not continue the accept loop as authenticated.
- **Related**: CRY (handshake integrity), TYP-003, CF-001 CERTS/AUTH chain

### [RET-004] Silent `runCatching` on relay TLS `startHandshake` — **OPEN**
- **Track**: return
- **Status**: OPEN
- **Evidence**: `RelayService.kt:418-422` — `runCatching { socket.startHandshake() }` discarded; code continues to `CellCodec.read` on possibly non-handshaked SSL. (Client `OrConnection` path calls `ssl.startHandshake()` without swallow — contrast.)
- **Risk**: High
- **Fix**: Propagate handshake failure (close socket / return); never proceed to VERSIONS on failed TLS.
- **Related**: RET-003 (auth chain), link handshake

### [RET-005] `Keypin.checkAndAdd` `Result` swallowed — **OPEN**
- **Track**: return
- **Status**: OPEN
- **Evidence**: `core/.../dir/DirVote.kt:196-199` — `runCatching { keypin.checkAndAdd(...) }` with no inspection of `Result.CONFLICT` / exceptions; vote still ingested (`:201-214`). `Keypin.Result` enum exists (`KeypinAndConsDiff.kt:16`) but caller ignores it. CF-008 notes check-then-add TOCTOU on the journal itself.
- **Risk**: High (RSA/Ed identity pin conflicts ignored → dirauth vote poison / identity swap)
- **Fix**: On `CONFLICT` reject or quarantine vote router; surface pin failure to caller; do not silent-`runCatching` security results.
- **Related**: CF-008, crypto/dirauth integrity

### [RET-006] CERTS parse failures silently dropped — **OPEN**
- **Track**: return
- **Status**: OPEN
- **Evidence**: `core/.../link/CertsCell.kt:42-48`, `:52-68`, `:110-113` — `runCatching { generateCertificate / ed ext }` with empty/`getOrNull` failure; malformed type-1/2/4 certs leave `rsaId`/`edId` null while `parse` still returns `Parsed` with partial data. TYP-006 notes ClassCast → null identity.
- **Risk**: High (identity mismatch checks skip when fingerprints never extracted — pairs with CF-001 null peer skip)
- **Fix**: Fail parse (throw / return error) when declared certCount requires identity material and extraction fails; do not equate “empty identity” with “no CERTS”.
- **Related**: OrConnection identity check, RET-003, TYP-006, CF-001

### [RET-007] Control `ADD_ONION` returns OK while publish `runCatching` fails silently — **OPEN**
- **Track**: return
- **Status**: OPEN
- **Evidence**: `control/.../ControlServer.kt:534-545` — replies `250-ServiceID` / `250 OK` immediately; background `runCatching { establishIntroPoints; publish }` only `System.err` on failure — controller never sees error Result / HS_DESC failure event.
- **Risk**: High (control API lies about onion readiness)
- **Fix**: Either await publish before 250, or return async status / HS_DESC events and document; never claim OK if intro/publish failed without event.
- **Related**: FAIL control semantics, HS host, CRY-001 (NULL auth amplifies)

### [RET-008] OnionTunnel commands: silent `runCatching` on refresh / dormant — **OPEN**
- **Track**: return
- **Status**: OPEN (Medium — outside Critical/High cap count but tracked)
- **Evidence**: `core/.../net/stack/OnionTunnel.kt:161-175` — `RefreshCircuits` / `SetDormant` wrap `client.refreshCircuits()` / `setDormant` in bare `runCatching` (no log, no rethrow, no scaffolding callback).
- **Risk**: Medium (VPN “newnym” / dormant appears applied while circuits stay live)
- **Fix**: Propagate to `scaffolding.onFailure` or log+surface; treat dormancy failure as fail-closed (block new TCP) if unset.
- **Related**: CF-007 dormant TOCTOU, RET-002 protect attach

## Conflicts

Cross-checks against other `docs/safety/domains/*.md` + empty mailbox:

| Clash | Domains | Note |
| --- | --- | --- |
| Teardown vs permanent `scope.cancel` | RET-001 **FIXED**, CF-001/002, FAIL-001, NUL-003, MEM-007 | Landed pattern: `teardownPartialStart` + `ensureScope` recreate. Peer FAIL/NUL/CF docs may still describe pre-fix evidence — prefer code + this status. |
| Fail-closed protect vs dial latency | RET-002 **FIXED**, MEM-006, OnionTunnel attach, NUL-004 | Clearing protector on `stop` pairs with fail-closed dial; do **not** “best-effort continue dial” under VPN. |
| Aggressive cancel vs FD close | RET-001 teardown, IO-007/008 | Order: close accepted sockets in `finally` / tracked set **then** cancel jobs. RET teardown that only `cancel()` amplifies FD leaks — listener `stop()` still cancel-heavy. |
| Auth Boolean enforce vs control NULL | RET-003 **OPEN**, CRY-001/002, FAIL-004 | Enforcing `OrAuthenticate.verify` is orthogonal to control NULL auth; do not weaken relay AUTH to match permissive control. |
| Keypin reject vs vote availability | RET-005 **OPEN**, CF-008 | Prefer reject/quarantine CONFLICT over accepting poisoned votes for “liveness”; fix Result swallow and TOCTOU together. |
| ADD_ONION await vs control timeout | RET-007 **OPEN**, FAIL | Prefer HS_DESC events + non-premature 250 over blocking forever; never silent-success. |
| Silent `runCatching` vs observability | RET-004/006/008 **OPEN**, TYP-006, CPU/logging | Security-path `runCatching` must not be empty; close/cleanup `runCatching` OK. |
| CERTS soft-null vs handshake FSM | RET-006 **OPEN**, CF-001, TYP-006 | Hard-fail CERTS parse + require CERTS before NETINFO; soft null identity enables CF-001 skip. |
| Mailbox | `/tmp/ktor-safety-pass` | Only `README.txt` present at pass time — no conflicting peer `domains/*.md` drops to merge. |
