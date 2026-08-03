# Domain: failure

**Scope:** fail-open vs fail-closed on control auth, SafeSocks, bootstrap-before-proxy, `KotlinTorEngine` / `TorDaemon.start` error paths.  
**Main sources:** `:core` (`TorDaemon`, `TorClient`, `SafeSocksPolicy`), `:proxy`, `:control`, `:android`.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| FAIL-001 | **Critical** | `startWithPorts` catch clears `running` but leaves SOCKS/daemon live |
| FAIL-002 | **Critical** | Proxy listeners opened when bootstrap incomplete (`DisableNetwork` / circuit swallow) |
| FAIL-003 | **High** | `daemon.start` failure leaves `started=true`; engine never `stop()` → restart stuck |
| FAIL-004 | **High** | Control NULL auth fails open when cookie + hashed password both off |
| FAIL-005 | **High** | SOCKS/HTTP accept with no bootstrap gate (unlike `OnionTunnel.ready`) |
| FAIL-006 | **High** | TUN `markBootstrapped()` does not check `client.isBootstrapped` / circuit |
| FAIL-007 | **Medium** | `SafeSocks` default off; `allowIpLiterals=true` nullifies policy |
| FAIL-008 | **Medium** | `isBootstrapped` = descriptors loaded, not `DONE` — soft fail-open |

---

### [FAIL-001] Engine start catch is fail-open (no teardown)
- **Track**: failure
- **Evidence**: `android/.../KotlinTorEngine.kt:99-143` — `running.compareAndSet(false,true)` then `daemon.start()` + `Socks5Server`/`HttpConnect`/`ControlServer`; `catch` only `running.set(false)`, Orbot error broadcast, `onError`
- **Risk**: Critical
- **Exploit logic**: Mid-start bind/control failure after SOCKS `start` leaves accepting listeners while `isRunning == false` and `onError` fired — callers treat engine as down; traffic still flows
- **Fix**: Shared teardown (stop all listeners, `daemon.stop()`, clear refs, reset flags) before `onError` — same as RET-001 / NUL-003
- **Related**: RET-001, NUL-003, CF-001

### [FAIL-002] Proxy traffic accepted without completed bootstrap
- **Track**: failure
- **Evidence**:
  - `TorDaemon.kt:157-161` — `DisableNetwork=1` returns after notice (no consensus/circuit)
  - `TorDaemon.kt:169-174` — circuit bootstrap exception swallowed if `client.isBootstrapped` (descriptors only)
  - `KotlinTorEngine.kt:103-129` — on any successful `daemon.start()` return: `bootstrapped.set(true)`, bind SOCKS/HTTP/DNS/Control, `onReady`
- **Risk**: Critical
- **Exploit logic**: Engine reports ready / Orbot `STATUS_ON` while streams cannot (or must lazily) build circuits; apps and TUN assume Tor path is live
- **Fix**: Fail-closed gate: do not bind app proxies or invoke `onReady` until `BootstrapPhase.DONE` (or explicit `DisableNetwork` mode that **refuses** SOCKS CONNECT). Surface partial bootstrap via status only
- **Related**: FAIL-005, FAIL-006, FAIL-008

### [FAIL-003] `daemon.start` throw leaves daemon started; engine does not stop
- **Track**: failure
- **Evidence**: `TorDaemon.kt:136` CAS `started=true` before bootstrap; throw on hard bootstrap fail (`172`); `stop()` is only place that clears `started` (`329-340`). `KotlinTorEngine.kt:137-142` catch never calls `daemon.stop()` / listener stop
- **Risk**: High
- **Exploit logic**: First `start` fails → `running=false` but daemon `started=true`. Retry `startWithPorts` → daemon throws `"already started"` → permanent start failure until process recreate
- **Fix**: On any engine start failure call `daemon.stop()` (and listener teardown). Optionally reset `started` in `TorDaemon.start` `finally` on unrecovered throw
- **Related**: FAIL-001, CF-001

### [FAIL-004] Control auth NULL path is fail-open
- **Track**: failure
- **Evidence**: `control/.../ControlServer.kt:241` adds `METHODS=NULL` when no cookie/password; `254-259` empty `AUTHENTICATE` succeeds; `271-274`, `321-325` also grant auth when both mechanisms off. Cookie path with cookie present is fail-closed (`302-328`)
- **Risk**: High (Critical if ControlPort bound non-loopback — IO-005 / CRY-002)
- **Exploit logic**: `CookieAuthentication 0` and no `HashedControlPassword` → any local (or remote) peer runs `SIGNAL`/`SETCONF`/`ADD_ONION` after empty AUTHENTICATE
- **Fix**: Keep NULL for loopback-only lab; reject non-loopback ControlPort unless cookie or hashed password configured; prefer default cookie (already `TorConfig.cookieAuthentication = true`)
- **Related**: CRY-002, IO-005

### [FAIL-005] SOCKS/HTTP have no bootstrap gate
- **Track**: failure
- **Evidence**: `proxy/.../Socks5Server.kt:57-75` accepts and dials immediately; `TorClient.connect` only errors on missing consensus (`217`, `290`, `307`). Contrast `OnionTunnel.kt:82-85` `if (!ready.get()) error("OnionTunnel not bootstrapped")`
- **Risk**: High
- **Exploit logic**: Once listeners exist (FAIL-002), clients get SOCKS success/failure races and may retry clearnet; no uniform “Tor not ready” rejection at accept
- **Fix**: Dialer/proxy refuse CONNECT with SOCKS failure until `DONE` (or consensus+circuit policy); align with OnionTunnel gate
- **Related**: FAIL-002

### [FAIL-006] TUN marks bootstrapped without Tor readiness check
- **Track**: failure
- **Evidence**: `VpnTunTorSession.kt:36-39` — `tunnel.markBootstrapped()` then `start()`; comment only about protect. Called from `KotlinTorVpnService.startTunStack` inside engine `onReady` (`KotlinTorVpnService.kt:64-67`)
- **Risk**: High
- **Exploit logic**: If `onReady` fires under FAIL-002, TUN TCP path opens (`OnionTunnel.openTcpFlow`) while client lacks circuit/consensus → app traffic fails open into error loops / leak risk if protect missing (RET-002)
- **Fix**: `markBootstrapped()` only when `client.isBootstrapped && (hasCircuit || DisableNetwork policy)`; else keep `ready=false`
- **Related**: FAIL-002, RET-002

### [FAIL-007] SafeSocks fail-open defaults / VPN override
- **Track**: failure
- **Evidence**: `TorConfig.kt:81` `safeSocks = false`; `NetworkPolicy.kt:190-195` — if `allowIpLiterals` then `allows` always `true`; `KotlinTorEngine.vpnDefaultConfig` sets `safeSocks=true` **and** `safeSocksAllowIpLiterals=true` (`181-182`); enforcement in `TorClient.connect` (`197-208`)
- **Risk**: Medium (CLI/default config); Low–Medium on Android VPN (intentional fake-IP)
- **Exploit logic**: Default daemon accepts IP-literal SOCKS destinations (DNS at client / exit mismatch class). VPN profile disables the only SafeSocks check by design
- **Fix**: Document; keep router/demo `safeSocks=true` without `allowIpLiterals` unless fake-IP path; consider allowlisting only Automap/fake-IP ranges instead of global bypass
- **Related**: deferred CLI default flip (SAFETY_AUDIT)

### [FAIL-008] `isBootstrapped` threshold is pre-DONE
- **Track**: failure
- **Evidence**: `TorClient.kt:115` — `progress >= LOADING_DESCRIPTORS`; `DONE` only after successful circuit (`160`). `TorDaemon.kt:172` uses this to **not** rethrow circuit failure
- **Risk**: Medium (enables FAIL-002)
- **Exploit logic**: Callers / daemon treat “bootstrapped” as usable Tor; C Tor controllers often wait for `PROGRESS=100` / circuit
- **Fix**: Split `directoryReady` vs `circuitReady`; gate proxies on circuit (or documented lazy-build mode)
- **Related**: FAIL-002

## Conflicts

- **Proxy gate vs DNSCrypt/OnionVPN ready contract**: Docs require SOCKS+DNSPort up before DNSCrypt; fail-closed “no bind until DONE” delays that plane — prefer bind control-only early, delay SOCKS CONNECT until DONE (or return SOCKS failure code without clearnet fallback).
- **VPN `safeSocksAllowIpLiterals` vs SafeSocks fail-closed**: Fake-IP TUN needs IP destinations — do not flip global allow; scope exception to Automap/fake-IP cookies only (tensions with FAIL-007 fix).
- **NULL control auth vs control-spec**: Spec allows NULL; safety requires bind policy (IO-005) rather than removing NULL entirely.
- **Teardown `daemon.stop()` cancels scope vs restart (CF-001)**: Fail-closed cleanup must recreate engine scope on next start — same conflict as RET/CF.
- **Fail-closed loopback bind vs product ports**: OnionVPN allocated loopback ports remain loopback; no conflict with FAIL-004 remediations.
