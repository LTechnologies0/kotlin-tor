# Domain: return

Ignored `Boolean`/`Result`, silent `runCatching`, and partial-success APIs in main sources (`core` / `proxy` / `control` / `android`). Cap ~8.

### [RET-001] `startWithPorts` partial success: no sibling teardown
- **Track**: return
- **Evidence**: `android/.../KotlinTorEngine.kt:99-143` — `running.compareAndSet(false,true)` then `daemon.start()`, sequential `Socks5Server` / role SOCKS / `DnsPortServer` / `HttpConnectProxy` / `ControlServer`; `catch` only `running.set(false)` + silent `runCatching` broadcast + `onError`. No `stop()` of already-bound listeners or daemon. `bootstrapped.set(true)` at `:104` before listeners bind; `onReady` at `:129` only on full success, but mid-failure leaves zombie SOCKS/HTTP/daemon with `isRunning==false`.
- **Risk**: Critical
- **Fix**: Shared teardown (stop listeners, clear refs, `daemon.stop`) in `catch` **before** clearing `running` / `onError`. Do not set `bootstrapped` until all requested ports bound. Align with FAIL-001 / NUL-003 / CF-001.
- **Related**: FAIL-001, NUL-003, CF-001, IO-007/008

### [RET-002] `protectSocket` `false` ignored on OR / PT dial
- **Track**: return
- **Evidence**: `core/.../net/NetworkPolicy.kt:154-156` — `OutboundBind.connect` calls `PlatformNatives.protectSocket(sock)` and discards `Boolean`, then `bind`/`connect`. `core/.../pt/PtSocksDialer.kt:23-26` same. `PlatformNatives.kt:226-235` returns `false` when protector missing, FD unavailable (`protector(-1)` then `false`), or host `protect` fails — dial still proceeds. OR path: `OrConnection` → `OutboundBind.connect` (default `protect=true`).
- **Risk**: Critical (Android VPN / OnionTunnel: unprotected SYN is captured by TUN → clearnet/routing loop / deanonymizing leak)
- **Fix**: When `socketProtector != null` (or `protect=true` under Android caps), fail-closed: throw / close socket if `protectSocket` returns `false`. Do not treat `protector(-1)` as optional best-effort for production VPN dials.
- **Related**: MEM-006 (clear protector on teardown), OnionTunnel `requireProtectAttached` (`OnionTunnel.kt:97-101` checks null only, not false)

### [RET-003] `OrAuthenticate.verify` Boolean ignored
- **Track**: return
- **Evidence**: `core/.../relay/RelayService.kt:449-457` — `val ok = OrAuthenticate.verify(...)` only `println`; parse failures logged; neither closes the link nor rejects subsequent CREATE2 when `ok==false`.
- **Risk**: High (relay accepts unauthenticated OR peer after AUTHENTICATE)
- **Fix**: If `!ok` (or parse fails), destroy connection / refuse further cells. Do not continue the accept loop as authenticated.
- **Related**: CRY (handshake integrity), FAIL auth

### [RET-004] Silent `runCatching` on relay TLS `startHandshake`
- **Track**: return
- **Evidence**: `RelayService.kt:418-422` — `runCatching { socket.startHandshake() }` discarded; code continues to `CellCodec.read` on possibly non-handshaked SSL.
- **Risk**: High
- **Fix**: Propagate handshake failure (close socket / return); never proceed to VERSIONS on failed TLS.
- **Related**: RET-003 (auth chain), link handshake

### [RET-005] `Keypin.checkAndAdd` `Result` swallowed
- **Track**: return
- **Evidence**: `core/.../dir/DirVote.kt:196-199` — `runCatching { keypin.checkAndAdd(...) }` with no inspection of `Result.CONFLICT` / exceptions; vote still ingested (`:201-214`).
- **Risk**: High (RSA/Ed identity pin conflicts ignored → dirauth vote poison / identity swap)
- **Fix**: On `CONFLICT` reject or quarantine vote router; surface pin failure to caller; do not silent-`runCatching` security results.
- **Related**: crypto/dirauth integrity

### [RET-006] CERTS parse failures silently dropped
- **Track**: return
- **Evidence**: `core/.../link/CertsCell.kt:42-48`, `:52-68` — `runCatching { generateCertificate / ed ext }` with empty `onFailure`; malformed type-1/2/4 certs leave `rsaId`/`edId` null while `parse` still returns `Parsed` with partial data.
- **Risk**: High (identity mismatch checks skip when fingerprints never extracted)
- **Fix**: Fail parse (throw / return error) when declared certCount requires identity material and extraction fails; do not equate “empty identity” with “no CERTS”.
- **Related**: OrConnection identity check, RET-003

### [RET-007] Control `ADD_ONION` returns OK while publish `runCatching` fails silently
- **Track**: return
- **Evidence**: `control/.../ControlServer.kt:509-520` — replies `250-ServiceID` / `250 OK` immediately; background `runCatching { establishIntroPoints; publish }` only `System.err` on failure — controller never sees error Result.
- **Risk**: High (control API lies about onion readiness)
- **Fix**: Either await publish before 250, or return async status / HS_DESC events and document; never claim OK if intro/publish failed without event.
- **Related**: FAIL control semantics, HS host

### [RET-008] OnionTunnel commands: silent `runCatching` on refresh / dormant
- **Track**: return
- **Evidence**: `core/.../net/stack/OnionTunnel.kt:161-175` — `RefreshCircuits` / `SetDormant` wrap `client.refreshCircuits()` / `setDormant` in bare `runCatching` (no log, no rethrow, no scaffolding callback).
- **Risk**: Medium (VPN “newnym” / dormant appears applied while circuits stay live)
- **Fix**: Propagate to `scaffolding.onFailure` or log+surface; treat dormancy failure as fail-closed (block new TCP) if unset.
- **Related**: CF command path, RET-002 protect attach

## Conflicts

Cross-checks against other `docs/safety/domains/*.md`:

| Clash | Domains | Note |
| --- | --- | --- |
| Teardown vs permanent `scope.cancel` | RET-001, CF-001, FAIL-001, NUL-003, MEM (restart) | Prefer **dedicated start-failure teardown** that stops listeners/daemon **without** cancelling engine root until final `stop`; OR recreate `CoroutineScope` on next `start` (CF Conflicts). Do not leave zombies to “fix” restart. |
| Fail-closed protect vs dial latency | RET-002, MEM-006, OnionTunnel attach | Clearing `PlatformNatives.socketProtector` on stop (MEM) must pair with RET-002 fail-closed; do **not** “best-effort continue dial” to keep connectivity tests green under VPN. |
| Aggressive cancel vs FD close | RET-001, IO-007/008 | Order: close accepted sockets in `finally` / tracked set **then** cancel jobs (IO Conflicts). RET teardown that only `cancel()` amplifies FD leaks. |
| Auth Boolean enforce vs control NULL | RET-003, CRY-002, FAIL-002 | Enforcing `OrAuthenticate.verify` is orthogonal to control NULL auth; do not weaken relay AUTH to match permissive control. |
| Keypin reject vs vote availability | RET-005, dirauth | Prefer reject/quarantine CONFLICT over accepting poisoned votes for “liveness”. |
| ADD_ONION await vs control timeout | RET-007, FAIL | Prefer HS_DESC events + non-premature 250 over blocking forever; never silent-success. |
| Silent `runCatching` vs observability | RET-004/006/008, CPU/logging | Security-path `runCatching` must not be empty; close/cleanup `runCatching` OK. |
