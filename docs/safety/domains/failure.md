# Domain: failure (re-audit)

**Pass:** 2026-08-03 · kotlin-tor SNAPSHOT  
**Scope:** fail-open vs fail-closed — engine/daemon start, bootstrap→proxy readiness, control NULL auth, SafeSocks, Android VPN protect policy, swallowed security failures (cross-RET), ADD_ONION readiness, daemon crash recovery.  
**Modules:** `:android` (`KotlinTorEngine`, `VpnTunTorSession`), `:core` (`TorDaemon`, `TorClient`, `NetworkPolicy`/`OutboundBind`, `PlatformNatives`, `CertsCell`, `RelayService`), `:proxy`, `:control`.  
**IDs:** `FAI-NNN` (canonical). Prior docs used `FAIL-NNN` — same numbers; treat `FAIL-00x` ≡ `FAI-00x`.  
**Cap:** ~8 Critical/High (RET-owned duplicates counted once under RET, listed here for fail-open policy only).

## Status rollup

| ID | Risk | Status | One-liner |
|----|------|--------|-----------|
| FAI-001 | Critical | **FIXED** | Partial-start catch/stop tear down listeners + daemon (`teardownPartialStart`) |
| FAI-002 | Critical | **FIXED** | `bootstrapped`/`onReady` gated on circuit `DONE` |
| FAI-003 | High | **FIXED** | Engine path clears sticky `started` via teardown; residual: raw `TorDaemon.start` throw |
| FAI-004 | High | **OPEN** | Control `METHODS=NULL` + empty AUTH fail-open when cookie+hash both off |
| FAI-005 | High | **OPEN** | SOCKS/HTTP accept with no bootstrap / `DONE` gate |
| FAI-006 | High | **OPEN** | `VpnTunTorSession` `markBootstrapped()` ignores `client.isBootstrapped` |
| FAI-007 | Medium | **OPEN** | SafeSocks default off; VPN `allowIpLiterals=true` nullifies policy |
| FAI-008 | Medium | **FIXED** | `isBootstrapped` = `DONE` (100); added `isCircuitReady` |
| FAI-009 | Critical | **FIXED** | VPN protect fail-closed — **canonical RET-002** |
| FAI-010 | High | **NEW** | No daemon crash recovery; `SupervisorJob` + sticky `started` on hard bootstrap throw |

**Counts:** FIXED 4 · OPEN 5 · NEW 1 · Critical/High open+new (capped): **FAI-004, FAI-005, FAI-006, FAI-010** (4).

**Top 3 open FAI IDs:** **FAI-005**, **FAI-004**, **FAI-006**

**RET cross-check (current code — do not re-ID):**

| RET | Risk | Verified | Notes for FAI |
|-----|------|----------|---------------|
| RET-001 | Critical | **FIXED** | ≡ FAI-001 |
| RET-002 | Critical | **FIXED** | ≡ FAI-009 fail-closed protect |
| RET-003 | High | **OPEN** | Auth verify ignore — FAI cites only; remediation under RET |
| RET-004 | High | **OPEN** | TLS `startHandshake` swallow |
| RET-005 | High | **OPEN** | Keypin Result swallow |
| RET-006 | High | **OPEN** | Soft CERTS → null identity |
| RET-007 | High | **OPEN** | ADD_ONION premature 250 OK |
| RET-008 | Medium | **OPEN** | OnionTunnel refresh/dormant silent |

---

## FIXED

### [FAI-001] Engine start catch is fail-open (no teardown) — **FIXED**
- **Track**: failure · alias FAIL-001 · **canonical remediation RET-001**
- **Status**: FIXED (Phase B / current sources)
- **Evidence (current)**:
  - `android/.../KotlinTorEngine.kt:147-155` — `catch` → `teardownPartialStart()`; `running`/`bootstrapped` cleared; then `onError`
  - `:159-170` — `stop()` same teardown + protector clear + `scope.cancel()`
  - `:192-205` — stops SOCKS / roleSocks / DNS / HTTP / Control, then `daemon.stop()`
  - `:184-188` — `ensureScope()` recreates scope + `TorDaemon` after cancel
- **Risk**: was Critical
- **Residual**: readiness still fail-open → **FAI-002**; FD drain on cancel → IO-007/008
- **Related**: RET-001, NUL-003, CF-001/002, MEM-006/007

### [FAI-003] `daemon.start` throw leaves `started=true`; engine never stops — **FIXED** (engine)
- **Track**: failure · alias FAIL-003
- **Status**: FIXED on `KotlinTorEngine` path; residual noted under **FAI-010**
- **Evidence (current)**: Engine catch calls `teardownPartialStart()` → `daemon.stop()` → `started.set(false)` (`TorDaemon.kt:329-340`). Restart via `ensureScope()` + new `TorDaemon`.
- **Residual**: Direct `TorDaemon.start()` still CAS `started=true` at `:136` before bootstrap; hard throw at `:172` does **not** clear `started` unless caller `stop()`s — library API sticky-start remains FAI-010.
- **Related**: FAI-001, RET-001, FAI-010

---

## OPEN

### [FAI-002] Proxy / Orbot “ready” without completed bootstrap — **FIXED** · Critical
- **Track**: failure · alias FAIL-002  
  **⚠ Naming clash:** `SAFETY_AUDIT.md` once labeled “IO-005 / FAIL-002” for Control non-loopback auth. That remedia­tion is **IO-005 / Control gate**, **not** this finding. FAI-002 = bootstrap readiness only.
- **Status**: FIXED
- **Evidence**: `TorClient.isBootstrapped` ≥ `DONE` (100); `isCircuitReady` added; `KotlinTorEngine` sets `bootstrapped`/`onReady` only when client reports DONE (DisableNetwork starts listeners without claiming circuit-ready)
- **Related**: FAI-005 residual (SOCKS still accepts before DONE), FAI-006 TUN

### [FAI-008] `isBootstrapped` threshold is pre-DONE — **FIXED** · Medium
- **Status**: FIXED (via FAI-002) — `isBootstrapped` now means DONE; `isCircuitReady` = DONE && hasCircuit

### [FAI-009] Android VPN `protectSocket` false discarded — **FIXED** · Critical
- **Track**: failure · **canonical ID RET-002**
- **Status**: FIXED — dial path fail-closed in NetworkPolicy / PtSocksDialer; do not regress

### [FAI-004] Control auth NULL path is fail-open — **OPEN** · High
- **Track**: failure · alias FAIL-004  
  **⚠ Naming clash:** `SAFETY_AUDIT` row “IO-001 / FAIL-004” meant SOCKS accept cap — **not** this ID. FAI-004 = NULL control auth.
- **Evidence**:
  - `ControlServer.kt:257-266` — `METHODS=NULL` when no cookie/password
  - `:279-284`, `:296-299` — empty / permissive AUTH succeeds when both mechanisms off
  - Mitigations landed: non-loopback Control requires cookie or hashed (`ControlServer.kt:47-52`, `KotlinTorEngine.requireSafeControl:215-221`); default `TorConfig.cookieAuthentication = true` (`TorConfig.kt:13`)
- **Risk**: High (Critical if ControlPort non-loopback **and** auth disabled — gate now blocks that combo)
- **Exploit logic**: Explicit `CookieAuthentication 0` + no hashed password → any peer on the bound interface runs SIGNAL/SETCONF/ADD_ONION after empty AUTHENTICATE
- **Fix**: Keep NULL for loopback lab only; refuse NULL entirely when bind is non-loopback (done); prefer never advertising NULL in production profiles; document SnapShot risk for loopback NULL
- **Related**: CRY-001/002, IO-005, RET-003 (orthogonal — do not weaken OR AUTH)

### [FAI-005] SOCKS/HTTP have no bootstrap gate — **OPEN** · High
- **Track**: failure · alias FAIL-005
- **Evidence**: `Socks5Server.kt:69-94` accepts and handles immediately after bind; no `DONE` / `hasCircuit` check. Contrast `OnionTunnel.kt:83-85` `if (!ready.get()) error(...)`.
- **Risk**: High
- **Exploit logic**: Once listeners exist under FAI-002, clients get SOCKS success/failure races; no uniform “Tor not ready” rejection at accept
- **Fix**: Refuse CONNECT with SOCKS failure until circuit-ready (or documented lazy-build); align with OnionTunnel gate
- **Related**: FAI-002, IO-009 (uncapped AP still amplifies)

### [FAI-006] TUN marks bootstrapped without Tor readiness check — **OPEN** · High
- **Track**: failure · alias FAIL-006
- **Evidence**: `VpnTunTorSession.kt:36-39` — `tunnel.markBootstrapped()` then `start()`; comment only about protect. `OnionTunnel.markBootstrapped()` (`:60-63`) sets `ready=true` unconditionally.
- **Risk**: High
- **Exploit logic**: If `onReady` fires under FAI-002, TUN TCP opens while client may lack circuit → error loops; pairs with unprotected dial if protect fails open (FAI-009 / RET-002)
- **Fix**: `markBootstrapped()` only when `client.isBootstrapped && (hasCircuit || explicit DisableNetwork refuse-TCP policy)`; else keep `ready=false`
- **Related**: FAI-002, RET-002 / FAI-009

### [FAI-007] SafeSocks fail-open defaults / VPN override — **OPEN** · Medium
- **Track**: failure · alias FAIL-007
- **Evidence**: `TorConfig.kt:81` `safeSocks = false`; `SafeSocksPolicy.allows` (`NetworkPolicy.kt:190-195`) — `allowIpLiterals` ⇒ always true; `routerDefaultConfig` sets `safeSocks=true` **and** `safeSocksAllowIpLiterals=true` (`KotlinTorEngine.kt:237-238`)
- **Risk**: Medium (CLI default); Low–Medium on VPN (intentional fake-IP)
- **Fix**: Document; scope IP allowlist to Automap/fake-IP ranges instead of global bypass
- **Related**: deferred CLI default (SAFETY_AUDIT)

---

## NEW

### [FAI-010] No daemon crash recovery; sticky `started` on hard bootstrap throw — **NEW** · High
- **Track**: failure
- **Evidence**:
  - No `CoroutineExceptionHandler` / auto-restart path in `TorDaemon` or `KotlinTorEngine` (repo grep: no crash-recovery hooks)
  - `TorDaemon` uses `SupervisorJob` (`TorDaemon.kt:47`) — child job failures do not cancel siblings and are not surfaced as engine restart
  - `start()` CAS `started=true` at `:136`; on hard bootstrap failure `:172` rethrows **without** `started.set(false)` — only `stop()` clears it (`:329-340`)
  - Engine path mitigates via FAI-001 teardown; raw daemon / embedded callers can wedge on “already started”
- **Risk**: High (permanent start failure after one hard bootstrap error; silent child death under SupervisorJob)
- **Fix**: `finally` reset `started` on unrecovered `start()` throw; optional supervised restart policy with backoff; surface fatal child exceptions to engine `onError` and refuse traffic until recovered
- **Related**: FAI-003 residual, CF-002, MEM-007, CPU-004

---

## Conflicts

Mailbox `/tmp/ktor-safety-pass/{return,io,memory,...}.md` + in-repo domains at write time.

| Clash | Domains | Resolution |
|-------|---------|------------|
| FAI-001 vs RET-001 | return, failure | **Same fix.** Status FIXED both; RET owns Boolean/teardown evidence; FAI owns fail-closed start policy. Prefer code + RET-001 line refs. |
| FAI-009 vs RET-002 | return, failure, memory | **Same bug.** Canonical remediation ID **RET-002**; FAI-009 is fail-open policy mirror. Do not open a second fix ticket. |
| RET-003/004/006/007 | return | Verified still OPEN in current code; FAI does **not** mint parallel Critical IDs (cap). Auth/CERTS/ADD_ONION stay RET-owned. |
| SAFETY_AUDIT “FAIL-002” = Control bind | SAFETY_AUDIT vs this file | **Mislabel.** Control non-loopback auth = IO-005. FAI-002 remains bootstrap/`onReady`. |
| SAFETY_AUDIT “FAIL-004” = SOCKS accept | SAFETY_AUDIT vs this file | **Mislabel.** SOCKS accept cap = IO-001. FAI-004 remains NULL control auth. |
| NULL auth vs bind gate | FAI-004, IO-005, CRY | Non-loopback require cookie/hash **landed**; residual is loopback NULL + intentional auth-off profiles. |
| Fail-closed DONE vs DNSCrypt/OnionVPN port contract | FAI-002/005 | Prefer bind Control early; delay SOCKS CONNECT success / `onReady` until DONE (or SOCKS reject without clearnet fallback). |
| VPN SafeSocks IP literals | FAI-007 | Fake-IP needs IPs — do not global-flip; allowlist Automap/fake-IP only. |
| Teardown vs scope cancel | FAI-001 FIXED, CF-002, MEM-007, CPU-004 | Recreate via `ensureScope`; move heavy close off Main (CPU-004 still OPEN). |
| Protect clear vs fail-closed dial | MEM-006 FIXED, FAI-009/RET-002 FIXED | Clear on `stop` OK; dial remains fail-closed when protector set. |
| Soft CERTS / auth ignore | RET-006, RET-003, CF | Hard-fail CERTS + enforce verify — complementary to FAI bootstrap gates; not renamed to FAI. |
| ADD_ONION premature OK | RET-007 | Prefer HS_DESC events; never silent 250 — control fail-open readiness, tracked under RET. |

---

## Return to board

| Bucket | IDs |
|--------|-----|
| **FIXED** | FAI-001, FAI-002, FAI-003, FAI-008, FAI-009 |
| **OPEN** | FAI-004, FAI-005, FAI-006, FAI-007 |
| **NEW** | FAI-010 |
| **Top 3 open** | FAI-005, FAI-004, FAI-006 |
