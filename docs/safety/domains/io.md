# Domain: io (re-audit)

**Pass:** 2026-08-03 · kotlin-tor SNAPSHOT  
**Scope:** proxy/control accept loops, binds, DNS/UDP flood, control cookie files, stream/socket close on cancel, `stop()` drain.  
**Modules:** `:proxy`, `:control`, `:core` (`ListenSpec` / `TorDaemon`), `:android` / `:cli` listeners.  
**Baseline verify:** `ProxyAcceptLimits`, `ControlServer` semaphore, `ListenSpec.isLoopbackHost()` — **present**.

## Counts

| Bucket | Count | IDs |
|--------|------:|-----|
| **FIXED** | 5 | IO-001, IO-002, IO-003, IO-004, IO-009 |
| **OPEN** | 4 | IO-005, IO-006, IO-007, IO-008 |
| **NEW** | 1 | IO-010 |
| Critical/High open+new (capped) | 4 | IO-005, IO-006, IO-007, IO-010 |

**Top 3 open IO IDs:** **IO-005**, **IO-006**, **IO-007**

---

## Baseline verification

| Control | Status | Evidence |
|---------|--------|----------|
| `ProxyAcceptLimits` | **OK** | `proxy/.../ProxyAcceptLimits.kt` — `DEFAULT_TCP=256`, `DEFAULT_DNS=128`, `DEFAULT_CONTROL=32`, `semaphore()` |
| SOCKS / HTTP gate | **OK** | `Socks5Server.kt:67,85-94`, `HttpConnectProxy.kt:46,58-67` — `tryAcquire` → close excess |
| DNSPort in-flight | **OK** | `DnsPortServer.kt:38,52-61` — drop when saturated (`continue`) |
| Control session gate | **OK** | `ControlServer.kt:39-44,63-72` — `Semaphore(32)`, close excess |
| `isLoopbackHost()` | **OK** | `TorConfig.kt:329-337` — empty/localhost/127.0.0.1/`::1` + `InetAddress.isLoopbackAddress` |
| Control non-loopback auth | **OK** | `ControlServer.kt:47-52` + `KotlinTorEngine.requireSafeControl` — require cookie or hashed password |
| Tests | **OK** | `proxy/.../ProxyAcceptCapTest.kt` — Socks/HTTP maxConcurrent=1 closes excess |

---

## FIXED

### [IO-001] SOCKS5 accept concurrency cap — FIXED
- **Track**: io
- **Evidence**: `Socks5Server.kt:67,85-94` — `gate.tryAcquire()`; on fail `sock.close()`; release in `finally`. Defaults `ProxyAcceptLimits.DEFAULT_TCP` (256).
- **Risk**: was Critical
- **Fix**: landed
- **Related**: MEM-003, CPU-001, IO-009 (secondary AP still uncapped)

### [IO-002] HTTP CONNECT accept concurrency cap — FIXED
- **Track**: io
- **Evidence**: `HttpConnectProxy.kt:46,58-67` — same fail-closed `tryAcquire` / close pattern.
- **Risk**: was Critical
- **Fix**: landed
- **Related**: IO-001, CPU-001

### [IO-003] DNSPort UDP in-flight flood — FIXED (DNSPort only)
- **Track**: io
- **Evidence**: `DnsPortServer.kt:38,49-61` — `Semaphore(DEFAULT_DNS=128)`; saturated → `continue` (drop, no `launch`/`resolve`).
- **Risk**: was Critical
- **Fix**: landed for DNSPort; SOCKS UDP ASSOCIATE residual → **IO-010**
- **Related**: MEM-001, CPU-001, BUF-001, IO-010

### [IO-004] ControlServer accept session cap — FIXED
- **Track**: io
- **Evidence**: `ControlServer.kt:39-44,63-72` — `DEFAULT_MAX_CONCURRENT=32`; `tryAcquire` → close; `ControlSession` still `socket.close()` in `finally` (`:145-149`).
- **Risk**: was High
- **Fix**: landed
- **Related**: CRY-001 / FAIL-004 (auth), CF teardown

---

## OPEN

### [IO-005] Non-loopback Socks/HTTP/DNS/CLI still bind as-is — OPEN
- **Track**: io
- **Status**: **PARTIAL** — Control gate FIXED; AP listeners residual OPEN (High)
- **Evidence**:
  - Control: `ControlServer.kt:47-52` refuse non-loopback without cookie/hashed; android `KotlinTorEngine.kt:215-221` mirrors
  - Socks/HTTP/DNS: no `isLoopbackHost` refuse in `Socks5Server.start` / `HttpConnectProxy.start` / `DnsPortServer.start` — bind `listen.host` as-is
  - Android AP: `requireSafeListener` (`KotlinTorEngine.kt:207-212`) **warns only**
  - CLI: `cli/.../Main.kt:228-250` starts Socks/Control/DNS/Trans/UdpGw from torrc with **no** loopback warn or refuse
- **Risk**: High (Critical if Control NULL + non-loopback — Control path now gated; Socks `0.0.0.0` still LAN exposure)
- **Fix**: Hard-refuse non-loopback Socks/HTTP/DNS/Trans unless explicit allow flag; CLI warn+refuse matching engine Control policy; keep Control require as-is
- **Related**: CRY-001, FAIL-004, TYP-001, NUL-007

### [IO-006] Control cookie file: default perms + CookieAuthFile ignored — OPEN
- **Track**: io
- **Evidence**:
  - `TorDaemon.kt:84` — `controlCookiePath` always `dataDirectory/control_auth_cookie` (ignores `TorConfig.cookieAuthFile`)
  - `:153-155` — `Files.write(controlCookiePath, cookie)` with **no** `setPosixFilePermissions(OWNER_READ, OWNER_WRITE)`
  - `cookieAuthFile` parsed (`TorConfig.kt:949`, field `:100`) unused by daemon
  - `ProcessOptions.cookieAuthFileGroupReadable` (`ProcessOptions.kt:38`) never applied
  - `ControlServer` PROTOCOLINFO still advertises `COOKIEFILE=` (`ControlServer.kt:269`)
- **Risk**: High (world-readable cookie on multi-user FS → Control takeover)
- **Fix**: Honor `CookieAuthFile`; write `0600` (group-read only if `CookieAuthFileGroupReadable=1`); keep data dir `0700`
- **Related**: CRY-006 (length/wipe), CRY-001

### [IO-007] Handler cancel skips socket close (Exception-only catch) — OPEN
- **Track**: io
- **Evidence**:
  - `Socks5Server.kt:200-205` — `catch (_: Exception)` closes pipe; `CancellationException` not caught; `finally` only removes `ConnectionTable` entry — **no** `local.close()` / socket close
  - `HttpConnectProxy.kt:114-116` — same Exception-only catch; **no** `finally` close
  - Contrast: `ControlSession` (`ControlServer.kt:145-149`) and `UdpTorGatewayServer.kt:42-46` close in `finally`
- **Risk**: High (FD / EXIT accounting leak under `stop()`/`cancel`)
- **Fix**: `try/finally { runCatching { local.close() / socket.close() } }` on all AP handlers; NonCancellable close if needed
- **Related**: RET-001, CF-001, MEM-003, IO-008, NUL-006

### [IO-008] stop() closes listener only; in-flight sockets rely on cancel — OPEN
- **Track**: io
- **Evidence**: `Socks5Server.stop` `:102-110`, `HttpConnectProxy.stop` `:75-83`, `DnsPortServer.stop` `:69-77`, `ControlServer.stop` `:80-88` — `server/socket.close()` + `job.cancel()`; no tracked accepted-`Socket` set. With IO-007, cancel does not drain FDs.
- **Risk**: Medium
- **Fix**: Concurrent set of accepted sockets (or handler Jobs); on `stop()`, cancel + close all; couple to accept semaphore
- **Related**: IO-007, RET-001, NUL-003

---

## NEW

### [IO-009] Secondary AP acceptors capped — **FIXED**
- **Track**: io
- **Status**: FIXED
- **Evidence**: `TransparentProxy`, `UdpTorGatewayServer`, `FixedTorTunnel`, `FtpTorProxy`, `BilingualProxyServer` — `ProxyAcceptLimits.semaphore(DEFAULT_TCP)` + `tryAcquire` → close → `finally` release (Socks5Server pattern). `ProxyAcceptCapTest` covers TransparentProxy + FixedTorTunnel `maxConcurrent=1`.
- **Risk**: was Critical
- **Related**: IO-001, MEM-003, CPU-001

### [IO-010] SOCKS UDP ASSOCIATE clearnet relay uncapped flood — NEW
- **Track**: io
- **Evidence**: `Socks5Extended.kt:130-174` — per ASSOCIATE session `DatagramSocket` relay loop; when client hint is `0.0.0.0` (`expected=null` at `:138-141`) any source may inject UDP; no per-datagram budget / rate limit. Session count gated by Socks accept (IO-001) but **bytes/pps inside** session unbounded. DNSPort path fixed separately (IO-003).
- **Risk**: High (amplification / clearnet UDP abuse via ASSOCIATE)
- **Fix**: Per-session token bucket / max datagrams; reject wildcard client hint unless explicit allow; drop when saturated
- **Related**: IO-003, BUF-001, CPU framing

---

## Conflicts (live)

Mailbox `/tmp/ktor-safety-pass/{memory,cpu,return,type,bounds}.md` + `docs/safety/domains/*` at write time.

| Live note | Source | Resolution |
|-----------|--------|------------|
| SOCKS/HTTP/DNS/Control accept caps **landed** | code + this pass IO-001..004 FIXED; cpu.md / memory.md agree | Do not reopen IO-001..004. Caps ≠ CPU-001 / MEM-003 closed. |
| MEM claims “IO-001 still documents unbounded SOCKS” | memory.md Conflicts (live) vs **stale** prior `io.md` | **Resolved this pass** — IO-001..004 FIXED; residual uncapped AP → **IO-009** (same list MEM-003 cites: Ftp/Transparent/Bilingual/FixedTor/UdpGw). |
| Accept semaphore vs ConnLimit | memory.md MEM-003 | Prefer **both**: fail-closed refuse at accept **and** ConnLimit on `ConnectionTable.add`. |
| Caps vs decrypt storm | cpu.md CPU-001 | Keep fail-closed `tryAcquire` (no blocking `acquire` on accept); add cell/crypto budget separately; do not raise `DEFAULT_TCP=256`. |
| UDP flood drop vs framing CPU | cpu.md CPU-005, BUF | DNSPort drop-before-resolve FIXED (IO-003); ASSOCIATE residual → IO-010; fix O(n²) `ArrayList` independently. |
| RET teardown vs FD close | return.md RET-001 FIXED, IO-007/008 | Order: close accepted sockets in `finally` / tracked set **then** cancel. Listener `stop()` still cancel-heavy → IO-008 OPEN. |
| Async stop (CPU-004) vs IO-007 | cpu.md | Moving teardown off Main must still finally-close sockets before cancel. |
| Control bind gate vs NULL auth | CRY-001 / FAIL-004 / type TYP-001 | Control non-loopback require cookie/hash **landed**; residual IO-005 is AP bind; do not reopen NULL for remote. |
| Cookie file vs wipe/length | CRY-006 | IO-006 `0600`/CookieAuthFile complementary to 32-byte enforce + wipe. |
| MEM-001 FakeIp FIXED | memory.md | IO-003 no longer blocked on cookie map growth; flood control stays DNS in-flight + IO-010. |
| FakeIp / ListenSpec | TYP-001 | Parse must not “fix” by binding weird hosts as `0.0.0.0`. |
| Android warn-only vs CLI silence | IO-005 | Prefer hard refuse + opt-in; keep loopback defaults (`routerDefaultConfig`). |
