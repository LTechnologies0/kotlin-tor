# Domain: io

Scope: proxy/control accept loops, binds, DNS/UDP flood, control cookie files, stream/socket close.
Modules: `:proxy`, `:control`, `:core` (TorDaemon / ListenSpec), `:android` / `:cli` listeners.

### [IO-001] SOCKS5 accept loop has no concurrency cap
- **Track**: io
- **Evidence**: `proxy/src/main/kotlin/org/kotlintor/proxy/Socks5Server.kt:64-73` — `while (isActive) { ss.accept(); launch { handle(sock) } }` with no semaphore / max clients. Same pattern on `TransparentProxy.kt:48-50`, `UdpTorGatewayServer.kt:39-41`, `FixedTorTunnel` / `FtpTorProxy` accept loops.
- **Risk**: Critical
- **Fix**: Shared `Semaphore(connLimit)` (align with `TorConfig.connLimit` / sandbox nofile); if `tryAcquire` fails, `sock.close()` immediately (fail-closed, no wait). Apply to all AP TCP acceptors.
- **Related**: IO-002, MEM-003, CPU-001, FAIL-004

### [IO-002] HTTP CONNECT accept loop uncapped
- **Track**: io
- **Evidence**: `proxy/src/main/kotlin/org/kotlintor/proxy/HttpConnectProxy.kt:52-54` — identical `accept` → `launch { handle }` without bound.
- **Risk**: Critical
- **Fix**: Same accept-cap helper as IO-001; refuse excess with TCP close (no HTTP response required).
- **Related**: IO-001, CPU-001

### [IO-003] DNSPort UDP receive launches unbounded work (amplification)
- **Track**: io
- **Evidence**: `proxy/src/main/kotlin/org/kotlintor/proxy/DnsPortServer.kt:42-47` — every datagram `launch { handleQuery }` → `dialer.resolve` (`:64-68`). No rate limit, client policy, or in-flight cap. SOCKS UDP ASSOCIATE clearnet relay (`core/.../Socks5Extended.kt:130-178`) similarly accepts UDP without flood budget when client hint is `0.0.0.0`.
- **Risk**: Critical
- **Fix**: In-flight `Semaphore` (e.g. 64); drop datagrams when saturated; optional per-source token bucket; do not spawn Tor RESOLVE under flood. Cap SOCKS UDP ASSOCIATE sessions under IO-001.
- **Related**: MEM-001 (FakeIpDnsCookies growth on other DNS path), CPU-001, BUF-001

### [IO-004] ControlServer accept loop uncapped
- **Track**: io
- **Evidence**: `control/src/main/kotlin/org/kotlintor/control/ControlServer.kt:49-52` — each accept spawns `ControlSession` (event collector + line loop) with no session limit.
- **Risk**: High
- **Fix**: Cap concurrent control sessions (e.g. 16–32); close excess before `ControlSession.run()`. Prefer stricter cap than SOCKS.
- **Related**: CRY-002 / FAIL-002 (auth × bind), CF-001 (stop vs mid-start sessions)

### [IO-005] Listeners bind caller/`torrc` host as-is (`0.0.0.0` allowed)
- **Track**: io
- **Evidence**: `ListenSpec.parse` accepts any `host:port` (`core/.../config/TorConfig.kt:329-337`). Binds: `Socks5Server.kt:59`, `HttpConnectProxy.kt:47`, `DnsPortServer.kt:36`, `ControlServer.kt:44`. Defaults are loopback (`TorConfig.kt:10-11`, `KotlinTorEngine.vpnDefaultConfig` `:178-179`), but CLI `Main.kt:235-240` starts whatever torrc specifies — e.g. `SocksPort 0.0.0.0:9050` / `ControlPort 0.0.0.0:9051` / `DNSPort 0.0.0.0:…`.
- **Risk**: High (Critical if Control/Socks exposed with NULL auth — see CRY-002)
- **Fix**: Refuse non-loopback Control/Socks/HTTP/DNS unless explicit allow flag **and** (cookie or hashed password for Control). Warn at start when `host` is `0.0.0.0`/`::`/`*`.
- **Related**: CRY-002, FAIL-002

### [IO-006] Control cookie file: default perms + CookieAuthFile ignored
- **Track**: io
- **Evidence**: `TorDaemon.kt:84` always uses `dataDirectory/control_auth_cookie`; `:153-155` `Files.write(controlCookiePath, cookie)` with no `OWNER_READ/WRITE`-only chmod. `TorConfig.cookieAuthFile` parsed (`TorConfig.kt:938`, field `:100`) but never consulted by daemon/control. `cookieAuthFileGroupReadable` (`ProcessOptions.kt:37`) never applied. `ControlServer.kt:243-244` advertises `COOKIEFILE=` in PROTOCOLINFO before AUTHENTICATE.
- **Risk**: High
- **Fix**: Write cookie via `Files.write` + `setPosixFilePermissions(OWNER_READ, OWNER_WRITE)` (or `0600`); honor `CookieAuthFile` path; apply group-readable only when `CookieAuthFileGroupReadable=1`. Keep dir `0700` even when sandbox off.
- **Related**: CRY-001 (compare), CRY-002 (NULL auth)

### [IO-007] Handler cancel skips socket close (Exception-only catch)
- **Track**: io
- **Evidence**: `Socks5Server.kt:178-183` — `catch (_: Exception)` then close; `CancellationException` is not `Exception`, so `finally` cleans `ConnectionTable` but does **not** close the client socket. Same in `HttpConnectProxy.kt:100-102` (no `finally` close at all on cancel). `ControlSession` correctly `socket.close()` in `finally` (`ControlServer.kt:120-125`).
- **Risk**: High
- **Fix**: `try/finally { runCatching { local.close() / socket.close() } }` on all AP handlers; catch `Throwable` only where needed, or use `NonCancellable` close. Ensure `stop()` drain closes in-flight fds.
- **Related**: RET-001 / CF-001 (teardown cancels jobs → triggers this leak), MEM-003

### [IO-008] stop() closes listener only; in-flight sockets rely on cancel
- **Track**: io
- **Evidence**: `Socks5Server.stop` `:80-87`, `HttpConnectProxy.stop` `:61-68`, `DnsPortServer.stop` `:54-61`, `ControlServer.stop` `:59-66` — `server/socket.close()` + `job.cancel()`; no tracked set of accepted `Socket`s. Combined with IO-007, stop/restart can leave half-open clients and EXIT/AP accounting entries until GC/timeout.
- **Risk**: Medium
- **Fix**: Register accepted sockets (or handler Jobs) in a concurrent set; on `stop()`, cancel + close all. Tie acquire/release to IO-001 semaphore.
- **Related**: IO-007, RET-001, NUL-003

## Conflicts
- **IO-001/002/003/004 vs CPU-001 / MEM-003 / FAIL-004**: Aligned — prefer fail-closed close/drop over queue-wait under load (do not `acquire()` blocking in accept thread).
- **IO-005 vs CRY-002 / FAIL-002**: Aligned — non-loopback Control requires cookie or hashed password; IO owns bind gate, crypto/failure own auth.
- **IO-005 vs VPN / multi-iface product needs**: Allow non-loopback only with explicit opt-in; OnionVPN/HEV path should keep loopback Socks (`vpnDefaultConfig`). Do not weaken IO-005 for “convenience binds”.
- **IO-006 vs `CookieAuthFileGroupReadable`**: Intentional group-read clashes with default `0600`. Resolve: default owner-only; group bit only when the torrc flag is set.
- **IO-007 vs RET-001 / CF-001 teardown**: Fail-closed engine teardown that `cancel()`s listener jobs **amplifies** FD leaks unless IO-007/008 land first (or in the same change). Order: close-in-`finally` → then aggressive cancel/teardown.
- **IO-003 vs MEM-001**: DNS flood fix should drop before resolve/cookie insert; cookie LRU alone is insufficient under UDP flood.
