# Safety audit board (shared)

**Repo:** kotlin-tor · **Status:** 0.1.0-SNAPSHOT
**Sources:** `docs/safety/domains/*.md` (12-domain parallel auditors + parent synthesis).

## memory


Scope: main Kotlin (`core` / `proxy` / `control` / `android` / `cli`). Cap ~8 strongest findings.

### [MEM-001] FakeIpDnsCookies host→ip maps never expire
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/net/stack/FakeIpDnsCookies.kt:21-24`, `:38-59`, `:112-116` — `flushExpired` removes only `v4`/`v6`; `v4ByHost`/`v6ByHost` retain every `isolation|host` forever; flood of unique names grows all four maps
- **Risk**: High
- **Fix**: In `flushExpired`, drop `*ByHost` entries whose IP is missing/expired; hard-cap (e.g. 8192) with LRU/FIFO eviction of both directions together
- **Related**: IO-003 (DNSPort flood), CF-002 (check-then-insert)

### [MEM-002] TorClient.hopKeys and isolatedCircuits unbounded
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/TorClient.kt:96`, `:102`, `:283-297`, `:372-379`, `:246-253` — `ensureHopKeys` only inserts; `isolatedCircuits` keyed by isolation string with no max; `KeepAliveIsolateSOCKSAuth` sets dirty timeout ≈ infinity so circuits are not reclaimed on reuse path
- **Risk**: High
- **Fix**: Cap hop-key cache (evict FPs not referenced by live circuits); cap isolated circuits (LRU close+remove); do not treat KeepAlive as unbounded retention without an absolute max
- **Related**: CF-003 (map ops under `mutex`)

### [MEM-003] ConnectionTable global map has no ConnLimit
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/link/ConnectionSt.kt:155-179`, `:184-211` — process-wide `ConcurrentHashMap`; `add`/`new*` never check `config.connLimit`; `clear()` only used in tests; missed `remove` on error paths retains handles
- **Risk**: High
- **Fix**: Enforce soft max on `add` (reject/close when over ConnLimit); audit AP/OR/DIR accept paths for `remove` in `finally`; optional idle sweep
- **Related**: IO-001..004 (unbounded accept → table growth)

### [MEM-004] HsCache side maps unbounded; TTL clean never scheduled
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/hs/HsCache.kt:41-44`, `:112-128`, `:155-168` — `trimDir`/`trimClient` only for `asDir`/`asClient`; `introByService` and `dirConnByKey` have no max; `cleanAsDir`/`cleanAsClient` exist but are never called from main (only `storeAsDir` from `OnionService.kt:450`)
- **Risk**: Medium
- **Fix**: Bound intro/dirConn maps; call `cleanAs*` on a daemon timer / before store; wire `MaxHSDirCacheBytes` / `handleOom` to production OOM path
- **Related**: —

### [MEM-005] Circuit.close leaves CircuitList / CircuitManager.open / OR connections
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt:703-708` (`close` unregisters streams only), `:775-776`, `:868`, `:892` — success path `CircuitList.put` + `open[circId]=path`; `close()` does not `CircuitList.remove` or `open.remove`; `connections` getOrPut never pruned
- **Risk**: High
- **Fix**: On close: `CircuitList.remove(id)`, remove from `CircuitManager.open`, drop idle `OrConnection` when last circuit unregisters; clear both maps on NEWNYM/daemon stop
- **Related**: MEM-002 (isolated circuit close path)

### [MEM-006] Static PlatformNatives.socketProtector retains VPN callback
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/os/PlatformNatives.kt:156-157`; `android/src/main/kotlin/org/kotlintor/android/KotlinTorEngine.kt:47-52`, `:147-158` — setter installs lambda capturing `VpnTunnel`/`VpnService.protect`; `stop()` never sets `PlatformNatives.socketProtector = null`
- **Risk**: High
- **Fix**: Clear static protector in `stop()` / teardown; prefer weak/engine-scoped holder over process-global mutable
- **Related**: RET-001 (partial-start teardown), RET-002

### [MEM-007] CoroutineScope cancel without restart; dual scopes; orphan defaults
- **Track**: memory
- **Evidence**: `android/.../KotlinTorEngine.kt:32-33`, `:100`, `:156` — `scope.cancel()` permanently kills engine Job; `TorDaemon` owns nested scope; `KotlinTorVpnService.kt:21`, `:59`, `:95` — second root scope; `dir/TorDaemonDirAuthCluster.kt:80`, `:127` — default `CoroutineScope(SupervisorJob()+Default)` if caller omits parent (cancelled only when `stopPublishLoops` gets that scope)
- **Risk**: Medium
- **Fix**: Recreate engine scope on next `start`, or cancel child Job only; share one supervised tree with VpnService; never default-construct orphan scopes in library APIs (require explicit parent)
- **Related**: CF-001, RET-001 / RET Conflicts (restartability)

### [MEM-008] Missing .use on certificate streams and InflaterInputStream
- **Track**: memory
- **Evidence**: `core/src/main/kotlin/org/kotlintor/link/OrCertMaterial.kt:147-148` — `Files.newInputStream(...)` not closed; `core/src/main/kotlin/org/kotlintor/dir/DirectoryClient.kt:191` — `InflaterInputStream(...).bufferedReader(...).readText()` without `.use` (native zlib state / FD)
- **Risk**: Medium
- **Fix**: `Files.newInputStream(path).use { cf.generateCertificate(it) }`; `InflaterInputStream(...).use { it.bufferedReader().readText() }`
- **Related**: —


## io


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


## cpu


**Scope:** main Kotlin (`:core`, `:proxy`, `:control`, `:android`). Focus: busy-wait, ReDoS / regex thrash, string|byte-in-loop, Android main-thread I/O via `KotlinTorEngine`, cell decrypt storms, spin locks.  
**Cap:** ~8 findings. Accept-path concurrency caps (`ProxyAcceptLimits`) already land under IO; this domain covers residual **CPU** cost.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| CPU-001 | **High** | Per-cell multi-hop peel/encrypt with no crypto budget → decrypt storm under load |
| CPU-002 | **Critical** | KIST `LinuxTcpInfo.query` forks `python3` per refill on the write path |
| CPU-003 | **High** | OR write-budget soft-spin (≤64×`delay(1)`) under `writeMutex` |
| CPU-004 | **High** | `KotlinTorEngine.stop` / VpnService teardown does sync socket+daemon work on caller (often Main) |
| CPU-005 | **High** | SOCKS UDP frame accumulate uses `ArrayList<Byte>` + `removeAt(0)` → O(n²) |
| CPU-006 | **Medium** | Hot parsers recompile `Regex("\\s+")` / `matches(Regex(...))` per line/token |
| CPU-007 | **Medium** | Untrusted text × regex (`findAll` / consdiff / control) → ReDoS-class CPU |
| CPU-008 | **Medium** | Soft busy-waits: `StreamShaper` pause spin, `AddressSet` CAS, PT CMETHOD poll-sleep |

---

### [CPU-001] Cell decrypt / encrypt storm (no crypto budget)
- **Track**: cpu
- **Evidence**:
  - `core/.../circuit/Circuit.kt:134-136` — every inbound `RELAY`/`RELAY_EARLY` calls `layers.decryptRelay`
  - `core/.../circuit/CircuitCrypto.kt:177-191` — peels **all hops** (AES-CTR+digest or CGO UIV) until recognized
  - `core/.../relay/RelayService.kt:501-509`, `:828-842` — relay path `peelFromClient` per cell; CGO copies full cell
  - Outbound: `encryptRelay` walks hops (`CircuitCrypto.kt:163-174`); padding `flushPendingDrops` sends DROP cells in a tight loop (`CircuitPaddingMachines.kt:179-185`)
- **Risk**: High
- **Fix**: Keep IO accept caps; add per-circuit / per-OR **cell or CPU token budget** (drop or queue when exhausted). Prefer in-place CGO buffers; rate-limit DROP bursts; avoid `System.err` on hot undecryptable path (`Circuit.kt:138`).
- **Related**: IO-001..003 (handler caps reduce spawn rate but not cells/sec once connected), MEM-003, CRY constant-time (do not weaken crypto for speed)

### [CPU-002] KIST TCP_INFO via per-call `python3` process
- **Track**: cpu
- **Evidence**:
  - `core/.../os/LinuxTcpInfo.kt:29-78` — `ProcessBuilder("python3", "-c", …)` + `waitFor(2s)` on every `queryFd`
  - `core/.../link/OrConnection.kt:399-421` — `kistSocketInfo()` inside write soft-spin; `:454-455` refill before each mux flush item when KIST / KIST_LITE
- **Risk**: Critical (if `SchedulerType.KIST` selected on Linux)
- **Fix**: Native `getsockopt(TCP_INFO)` / JNI or cached sample (e.g. ≤1/tick); never fork a process on the cell write path. Until then: default away from full KIST on Android/embed; treat python path as debug-only.
- **Related**: CPU-003 (spin × process = lock hold amplification), IO write path

### [CPU-003] Write-budget soft-spin under `writeMutex`
- **Track**: cpu
- **Evidence**: `core/.../link/OrConnection.kt:417-423` — `while (!writeBudget.tryAllowFull(...)) { refill(...); if (++spins > 64) break; delay(1) }` inside `writeMutex.withLock`
- **Risk**: High
- **Fix**: Release mutex before wait; use suspend condition / channel credit (same pattern as `CircuitFlowControl.packageCredit`); after budget break, re-queue cell instead of spinning. Cap refill cost (CPU-002).
- **Related**: CPU-002, ChannelSchedulerPending drain fairness

### [CPU-004] Android engine stop / protect / TUN on caller thread
- **Track**: cpu
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:100-144` — `scope` = `Dispatchers.Default`; `onReady` / `onError` / Orbot `sendBroadcast` run there (not Main) — OK for UI if host hops
  - `:147-158` `stop()` synchronously closes SOCKS/DNS/HTTP/Control, `daemon.stop()` (relay/PT/onion/`scope.cancel`/pid file) — **no** `Dispatchers.IO`
  - `android/.../KotlinTorVpnService.kt:90-96` — `onDestroy` (Main) → `engine?.stop()` + TUN close
  - `:35-47` `VpnTunnel.protect` / `Builder.establish()` invoked from engine/TUN callbacks (Default) — protect is binder IPC; establish is heavy I/O
- **Risk**: High (ANR / jank when Service/Activity calls `stop`; Medium if host `onReady` touches Views without Main hop)
- **Fix**: Make `stop()`/`teardown` async on `Dispatchers.IO` (or `scope.launch` + join with timeout); document that `onReady`/`onError` are **not** Main; require UI hosts to `withContext(Main)`. Keep protect off Main but bound/fast.
- **Related**: CF-001 / RET-001 / MEM-007 (teardown + scope lifecycle), FAIL-001

### [CPU-005] Byte-in-loop O(n²) on SOCKS UDP framing
- **Track**: cpu
- **Evidence**: `core/.../net/FramingProtocols.kt:341-352` (and `:375+`) — `ArrayList<Byte>()`; per read `acc.add`; parse then `repeat(used) { acc.removeAt(0) }`. Same class of cost: `ProxyFrontends.kt` / `RelayService.kt:690-705` `ArrayList<Byte>` for RESOLVED; `CircuitCrypto.buildExtend2Data` (`:215-225`) boxes every handshake byte.
- **Risk**: High on UDP ASSOCIATE / large datagrams; Medium on EXTEND2/RESOLVE
- **Fix**: `ByteArray` + offset/length or `ByteArrayOutputStream` / circular buffer; `System.arraycopy` discard; never `removeAt(0)` in a loop.
- **Related**: BUF domain (buffer shape), IO UDP flood

### [CPU-006] Regex recompiled in directory / config / policy hot paths
- **Track**: cpu
- **Evidence**:
  - `TorConfig.kt` — many `line.split(Regex("\\s+"))` inside parse switch (`:619+`)
  - `BandwidthVote.kt`, `DirList.kt`, `ProcessDescsAndAuthMode.kt`, `ControlServer.kt` — same per-token pattern
  - `KeypinAndConsDiff.kt:173` — `cmd.matches(Regex("""\d+(,\d+)?d"""))` **allocates Regex each command**
  - `NetworkPolicy.kt:180`, `RouterSetAndDlStatus.kt:44` — `matches(Regex(...))` per host/token
- **Risk**: Medium (startup / consensus / control); compounds under malicious large torrc or vote bodies
- **Fix**: `private val WS = Regex("\\s+")` (or `companion`) reuse; prefer `split(' ')` / index scanners for whitespace; precompile fingerprint / consdiff command patterns.
- **Related**: CPU-007, BUF-002

### [CPU-007] ReDoS-class regex CPU on untrusted protocol text
- **Track**: cpu
- **Evidence**:
  - `BinaryAppProtocols.kt:163-174` — `ATTR = Regex("""(\w+)=["']([^"']*)["']""")` then `findAll(t)` on full XMPP open (attacker-controlled size)
  - `ControlServer.kt:616` — `Regex("""(?m)^hs_blinded_id=(\S+)""")` constructed in handler path
  - `KeypinAndConsDiff.kt:168-178` — consdiff apply: mutable line list + `removeAt` ranges (CPU + allocation); regex per delete cmd (CPU-006)
- **Risk**: Medium (no nested `(a+)+` found in main; still unbounded match work on huge inputs)
- **Fix**: Cap input length before regex; use linear scanners for attrs / consdiff opcodes; precompile once; reject oversized control/HS/XMPP frames early (align IO/BUF caps).
- **Related**: CPU-006, IO control/DNS caps

### [CPU-008] Soft busy-waits and CAS spins
- **Track**: cpu
- **Evidence**:
  - `BytePipe.kt` `StreamShaper.awaitUnpaused` `:59-62` — `while (paused) delay(5)` (poll)
  - `AddressSet.kt:32-35` — unbounded `compareAndSet` spin on bloom word
  - `PtManager.kt:84-87` / `PtServerManager.kt` — `repeat(50) { … Thread.sleep(100) }` CMETHOD wait (blocking thread, ~5s worst)
  - `TorDaemonDirAuthCluster.kt:97-110` — quorum poll `Thread.sleep(50)` (dir-auth cluster path)
- **Risk**: Medium (AddressSet CAS normally short; pause/PT/auth polls waste CPU or block threads under stuck peers)
- **Fix**: Pause → `Mutex`/`CompletableDeferred`; PT wait → `Channel`/`withTimeout` on reader events; AddressSet keep CAS but avoid nesting under hot locks; dir-auth use suspending delay on IO dispatcher.
- **Related**: CPU-003 (prefer credit channels over spin), multithreading / CF


## type


Scope: main Kotlin (`core` / `proxy` / `control` / `android`). Focus: unsafe casts (`as` / `as?`), `Any?` bags, wrong enum/proto encodings, `ByteArray` vs `List` wire builders, `ListenSpec` misuse. Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| TYP-001 | **High** (Critical × IO-005) | `ListenSpec.parse` mishandles `unix:`, bare IPv6, flags, unbound ports |
| TYP-002 | **High** | `CircuitMux.MuxCircuit.policyData: Any?` + `as? CircEwma` erases policy type |
| TYP-003 | **High** | AUTH RSA digest API hashes SPKI; TLS exporter return forced `as ByteArray` |
| TYP-004 | **High** | Dual SUBPROTO encodings: Trunnel ASCII vs live binary `protocol_id‖cap` |
| TYP-005 | **High** | `roleSocks` positional `List` conflates dnsCrypt vs probe `ListenSpec` roles |
| TYP-006 | **High** | CERTS/TLS `as X509Certificate` / `as SSLSocket` — wrong type → silent drop |
| TYP-007 | **Medium** | `ArrayList<Byte>` wire builders + unnamed RESOLVED vs SOCKS ATYP codes |
| TYP-008 | **Medium** | `ConnectionTable` `as` after `add` + `hopKeys[fp]!!` (NUL-002) |

No standalone Critical-only type finding; strongest cluster is **High**, escalating to Critical when ListenSpec binds non-loopback / mis-parses (IO-005 / FAIL-004).

---

### [TYP-001] `ListenSpec.parse` type/shape misuse
- **Track**: type
- **Evidence**:
  - `config/TorConfig.kt:325-348` — `data class ListenSpec(host, port)`; `parse` uses `lastIndexOf(':')` then `toInt()`
  - `:342-347` — `unix:` excluded from host:port branch → falls to `ListenSpec("127.0.0.1", t.toInt())` → `NumberFormatException` on socket paths
  - Bare IPv6 (`::1`) / multi-colon hosts split on wrong colon; bracket form `[::1]:9050` only accidentally works
  - No `port in 0..65535` (INT-004); negative / oversize Int accepted into bind APIs
  - `TorConfig.kt:624-626` SocksPort strips tokens; `:631` ControlPort / `:641+` OR/ExtOR/Dir/Metrics/DNS pass raw `value` (flags → `toInt` fail or wrong host)
- **Risk**: High (Critical when mis-parse or `0.0.0.0` exposes control/proxy — IO-005 / FAIL-004)
- **Fix**: Typed parse result (`Tcp(host,port)` | `Unix(path)` | `Auto`); strip flags before parse; validate port; parse IPv6 with brackets; reject unix until AF_UNIX listeners exist
- **Related**: IO-005, INT-004, FAIL-004, ControlServer loopback gate

### [TYP-002] Circuit mux `policyData: Any?` unsafe cast bag
- **Track**: type
- **Evidence**:
  - `circuit/CircuitMux.kt:65` — `var policyData: Any? = null`
  - `:214` — `CircuitMuxPolicy.allocCircData` returns `Any?`
  - `:256` — EWMA allocates `CircEwma` as `Any`
  - `:259`, `:270` — `mc.policyData as? CircEwma ?: return` / `?: CircEwma()` — wrong/missing type silently disables EWMA or invents empty state
  - `link/OrConnection.kt:502` — `circuitMux.policy() as? EwmaCircuitMuxPolicy`
- **Risk**: High (priority inversion / unfair cell scheduling under policy swap; fail-open to FIFO/`minBy` quirks)
- **Fix**: Generic `CircuitMux<P>` or sealed `PolicyData`; typed `EwmaCircuitMuxPolicy` accessors; never `Any?` on hot path
- **Related**: CPU scheduling, CF mux attach

### [TYP-003] AUTH0003 digest / exporter return type confusion
- **Track**: type
- **Evidence**:
  - `link/OrAuthenticate.kt:79-80` — `sha256DerRsa` = `Digests.sha256(cert.publicKey.encoded)` (**SPKI** DER)
  - `link/CertsCell.kt:89-93` — live CID/SID path = SHA256 of **PKCS#1** bit string inside SPKI
  - `OrAuthenticate.kt:66-72` — reflection exporter `m.invoke(...) as ByteArray` (unchecked; non-`ByteArray` → CCE mid-handshake)
  - Live initiator uses `CertsCell.rsaIdentitySha256*` (`OrConnection.kt:305-306`); `sha256DerRsa` is still a public footgun
- **Risk**: High (wrong CID/SID if API reused; CCE aborts AUTH; type-divergent “same” digest)
- **Fix**: Delete or rename `sha256DerRsa` to call PKCS#1 path only; exporter: `as? ByteArray ?: error(...)`; single typed `RsaIdentitySha256` helper
- **Related**: RET-003 (verify ignored), CRY AUTH, CF-001 CERTS

### [TYP-004] Wrong SUBPROTO wire type (ASCII vs binary)
- **Track**: type
- **Evidence**:
  - `trunnel/TrunnelLite.kt:46-59` — `SubprotoRequestTrunnel.encode` = ASCII `Name=Ver` map (inventory claims link handshake / CREATE)
  - `circuit/CircuitExtensions.kt:115-134` — live ntor-v3 SUBPROTO = binary `protocol_id ‖ cap_number` (Relay=6 → `[0x02,0x06]`)
  - `:139-162` — decoder accepts **both** ASCII (if `=` present) and binary — ambiguous type on untrusted ext body
  - Elevation tests assert Trunnel ASCII round-trip, not wire parity with `CircuitExtensions`
- **Risk**: High (CREATE/CGO negotiation fails or mis-parses if Trunnel codec used on wire; ASCII branch on binary body with accidental `0x3D`)
- **Fix**: One codec = binary prop346; demote Trunnel ASCII to test-only / rename; reject ASCII on live path
- **Related**: Circuit CGO path, CRY handshake

### [TYP-005] `ListenSpec` role erased in `roleSocks` list
- **Track**: type
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:56-58` — `dnsCryptSocksPort` = `roleSocks[0]`, `probeSocksPort` = `roleSocks[1]`
  - `:108-116` — optional `dnsCryptSocks` / `probeSocks` each `+=` into same `CopyOnWriteArrayList`
  - Probe-only start → probe appears as dnsCrypt port; dnsCrypt-only → probe getter returns `-1` correctly but indices are untyped
- **Risk**: High (OnionVPN / DNSCrypt plane binds wrong loopback port; silent role swap)
- **Fix**: Named fields / map `enum class SocksRole { DNSCRYPT, PROBE }` → server; getters read by role not index
- **Related**: NUL-004 port `-1`, FAIL engine start, IO bind

### [TYP-006] Unchecked CERTS / TLS `as` casts
- **Track**: type
- **Evidence**:
  - `link/CertsCell.kt:43`, `:111` — `generateCertificate(...) as X509Certificate` inside `runCatching` → ClassCast → null identity (RET-006)
  - `link/OrCertMaterial.kt:147-148` — same cast on disk certs (no soft catch → hard CCE)
  - `relay/RelayService.kt:144`, `:161` — `createServerSocket() as SSLServerSocket`, `accept() as SSLSocket`
  - `link/OrConnection.kt:171` — `createSocket(...) as SSLSocket`; `:314` uses safer `as?`
  - `dir/AuthorityCert.kt:55-65` — `public as JrsaPublicKey`
- **Risk**: High (peer CERTS non-X.509 → silent missing RSA id; factory mismatch → listener death)
- **Fix**: `as? X509Certificate ?: fail-closed`; typed SSL factories returning SSL types; no identity progress without RSA_ID_X509
- **Related**: RET-006, CF-001, CRY link auth

### [TYP-007] `ByteArray` vs `List<Byte>` wire builders / address-type enums
- **Track**: type
- **Evidence**:
  - `relay/RelayService.kt:690-713` — RESOLVED built via `ArrayList<Byte>` + `+= Int` literal coerce + `byteArrayOf(...).toList()` then `toByteArray()`
  - Tor RESOLVED types `0x04`/`0x06` vs SOCKS `ATYP_IPV4=0x01` / `ATYP_IPV6=0x04` (`SocksCodec.kt:17-19`) — no shared sealed type; easy cross-protocol misuse
  - Similar `ArrayList<Byte>` builders: `circuit/CircuitCrypto.kt:215+`, `hs/OnionService.kt:79`, `net/FramingProtocols.kt:341+` (CPU-005 O(n²))
  - `Circuit.kt:434-457` `parseResolved` hard-codes magic ints (correct for Tor, untyped)
- **Risk**: Medium (wrong ATYP → empty/corrupt RESOLVED; allocation churn)
- **Fix**: `ByteArrayOutputStream` / `ByteBuffer`; `enum class ResolvedAddrType(val id: Int)`; never reuse SOCKS ATYP for relay cells
- **Related**: CPU-005, BND parseResolved TTL skip

### [TYP-008] ConnectionTable unchecked `as` + `hopKeys!!`
- **Track**: type
- **Evidence**:
  - `link/ConnectionSt.kt:184-211` — `add(...) as OrConnectionHandle` (and peers); `ConnectionCast` correctly uses `as?`
  - `TorClient.kt:107-109`, `:427-429` — `ensureHopKeys` then `hopKeys[fp]!!`
- **Risk**: Medium (CCE if `add` wrapping changes; NPE under eviction — NUL-002)
- **Fix**: Factories return concrete type without cast; `ensureHopKeys(): HopKeys`
- **Related**: NUL-002, MEM-002


## return


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


## bounds


**Scope:** main Kotlin — `copyOfRange` / index OOB, cell & relay payload lengths, link variable-cell sizes, DNS packet parse (`TunFakeDns` / DNSPort), unchecked array indexing on wire data.  
**Main sources:** `:core` (`cell`, `relay`, `link`, `circuit`, `net/stack`), `:proxy` (`DnsPortServer`). Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| BND-001 | **High** | `parseExtend2` indexes/`copyOfRange` with no remaining-length checks |
| BND-002 | **High** | `parseCreated2Payload` / EXTEND CREATED2 `hlen` → `copyOfRange` without size gate |
| BND-003 | **High** | `CellCodec.read` variable cells: u16 length uncapped (≤65535 alloc/read) |
| BND-004 | **High** | `OrAuthenticate.parse` `copyOfRange(4, 4+len)` without `payload.size` check |
| BND-005 | **Medium** | `RelayCell.toPayload` V0: no `length ≤ 509−11` before `copyInto` |
| BND-006 | **Medium** | `TunFakeDns.buildResponse` re-walks QNAME without bounds / `0xc0` checks |
| BND-007 | **Low** | `TunFakeDns.parseQuery` / DNSPort name walk — length checks present (keep) |
| BND-008 | **Medium** | `readU16be`/`readU32be` assume `offset+width` in-bounds (callers uneven) |

No standalone **Critical** OOB (uncaught process crash on hot path); High items are peer-driven `IndexOutOfBoundsException` / unbounded variable-cell read. Several High paths are wrapped in `try`/`runCatching` (fail to DESTROY/TRUNCATED/log) — still exception-as-control-flow, not fail-closed length validation.

---

### [BND-001] `parseExtend2` link-spec walk without remaining-length checks
- **Track**: bounds
- **Evidence**: `core/.../relay/RelayService.kt:1207-1237` — `data[i++]` for `nspec`/type/len; `data.copyOfRange(i, i + len)` and later `copyOfRange(i, i + hlen)` with no `i + … ≤ data.size` before access (contrast `LinkSpecifiers.parsePacked` which `require`s headers/bodies)
- **Risk**: High
- **Exploit logic**: Client sends peeled EXTEND2 with `nspec`/len/`hlen` past end of relay body → `IndexOutOfBoundsException` inside `handleExtend2` `try` → TRUNCATED path; still DoS of extend and noisy fail
- **Fix**: Before each read: `require(i + need <= data.size)`; reject oversized `nspec`; mirror `LinkSpecifiers.parsePacked`
- **Related**: BND-002, FAIL (exception-as-control-flow)

### [BND-002] CREATED2 / `parseCreated2Payload` trusts `hlen` for `copyOfRange`
- **Track**: bounds
- **Evidence**:
  - `circuit/CircuitCrypto.kt:205-207` — `hlen` from first two bytes; `payload.copyOfRange(2, 2 + hlen)` unchecked
  - `RelayService.kt:1070-1071` — same pattern on next-hop `CREATED2` during EXTEND2
  - Callers: `Circuit.kt:238`, `:252`, `:269` (first-hop create)
- **Risk**: High
- **Exploit logic**: Peer/next hop sets `hlen` so `2 + hlen > payload.size` (fixed cell still 509) → OOB on client bootstrap or mid-extend
- **Fix**: `require(payload.size >= 2 && hlen <= payload.size - 2)` (and optional max handshake size) before slice
- **Related**: BND-001, cell payload lengths

### [BND-003] Link variable cells: no max payload length
- **Track**: bounds
- **Evidence**: `cell/Cell.kt:63-69` — `readU16be` length then `input.readNBytes(len)` with no cap; variable cmds in `CellCommand` (VERSIONS, VPADDING, CERTS, AUTH_*, …)
- **Risk**: High
- **Exploit logic**: Peer advertises `len=65535` (e.g. VPADDING/CERTS flood) → large alloc + blocking read per cell on every OR accept path (`OrConnection.readLoop`, `RelayService` OR loop)
- **Fix**: Cap variable payload (align with C Tor / tor-spec practical max); refuse/close on oversize before `readNBytes`
- **Related**: MEM/IO OR accept, BUF

### [BND-004] `OrAuthenticate.parse` length field unchecked before slice
- **Track**: bounds
- **Evidence**: `link/OrAuthenticate.kt:120-126` — `require(payload.size >= 4)` then `copyOfRange(4, 4 + len)` without `4 + len <= payload.size`; `take(n)` later also unchecked vs remaining
- **Risk**: High
- **Exploit logic**: Initiator AUTHENTICATE variable cell with lying `len` → OOB; `RelayService.kt:451-457` catches via `runCatching` (log only)
- **Fix**: `require(4 + len <= payload.size)`; bounds inside `take`; fail-closed close link on auth parse failure
- **Related**: BND-003 (variable cell), CRY auth verify

### [BND-005] Relay V0 encode: length vs fixed cell capacity
- **Track**: bounds
- **Evidence**: `cell/Cell.kt:88-101` — `toPayload()` pads to `FIXED_PAYLOAD_LEN` but only `require(data.size <= length)`; no `length <= FIXED_PAYLOAD_LEN - 11` before `copyInto(out, 11, …)` (V1 path does check maxLen at `:116-117`)
- **Risk**: Medium
- **Exploit logic**: Mis-built `RelayCell` (length > 498) → `ArrayIndexOutOfBoundsException` on encode; parse path already checks length (`:150-151`)
- **Fix**: Same max as parse: `require(length <= Cell.FIXED_PAYLOAD_LEN - 11)`
- **Related**: cell payload lengths

### [BND-006] `TunFakeDns.buildResponse` QNAME copy without re-validation
- **Track**: bounds
- **Evidence**: `net/stack/TunFakeDns.kt:87-97` — `while` uses `len = query[i] & 0xff` then `out.put(query, i, 1 + len)` / `i += 1 + len` with no `i + 1 + len <= query.size`, no `0xc0` reject, no max labels/name (255); `ByteBuffer.allocate(512)` can `BufferOverflowException` on pathological question + AAAA answer
- **Risk**: Medium (today `handleQuery` only after `parseQuery`, which checks lengths and rejects compression — defense is call-order, not local)
- **Fix**: Reuse validated offsets from `parseQuery`, or duplicate `i + 1 + len` / compression / name-length caps; truncate safely on 512
- **Related**: BND-007, MEM-001 (fake-IP flood), IO-003

### [BND-007] DNS name parse length checks present (positive)
- **Track**: bounds
- **Evidence**:
  - `TunFakeDns.kt:36-62` — `raw.size < 12` null; `i + len > raw.size` null; compression `0xc0` null; QTYPE/QCLASS `i + 4`
  - `proxy/.../DnsPortServer.kt:89-102` — same `i + len` pattern
- **Risk**: Low (mitigated)
- **Fix**: Keep; add max labels / total name ≤ 255; ensure empty-label / missing NUL cannot fall through
- **Related**: BND-006, INT-001 (byte mask)

### [BND-008] `readU16be` / `readU32be` are unchecked helpers
- **Track**: bounds
- **Evidence**: `util/Bytes.kt:53-69` — index `buf[offset]` … `offset+width-1` with no size precondition; used on CREATE2 (`RelayService.kt:895-896` — OK when payload is fixed 509), CERTS, relay bodies, etc.
- **Risk**: Medium (depends on caller)
- **Fix**: Prefer checked helpers (`readU16beOrNull` / require size) at untrusted boundaries; audit CREATE2 path if short payloads ever constructed off wire
- **Related**: BND-001, BND-002


## crypto


Scope: `core/.../crypto/` (ntor / ntor-v3 / CGO / AES-CTR / CreateFast), control auth (`:control` SAFECOOKIE / COOKIE / HASHEDPASSWORD / NULL), `util` (`constantTimeEquals`, `secureWipe`, `SecureRandomSource`). Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| CRY-001 | **High** (Critical + IO-005) | Control NULL / empty-or-any password AUTHENTICATE fails open when cookie+hash unset |
| CRY-002 | **High** | Wire AUTH/MAC/KH compares use `contentEquals` (ntor, ntor-v3, hs-ntor, CreateFast) |
| CRY-003 | **High** | Ephemeral DH/seed material not wiped after handshake (NtorV3 / HsNtor / CreateFast / ClientState) |
| CRY-004 | **Medium** | CreateFast still client-callable; relay always accepts (`supportsCreateFast=true`) |
| CRY-005 | **Medium** | `secureWipe` = `fill(0)` only; AES-CTR/CGO keys have no destroy path |
| CRY-006 | **Medium** | Control cookie heap not wiped; SAFECOOKIE/COOKIE read does not enforce 32-byte length |
| CRY-007 | **Low** (mitigated) | Control COOKIE/SAFECOOKIE/S2K already use `constantTimeEquals` |
| CRY-008 | **Low** (ok) | Handshake RNG via `SecureRandomSource` / `SecureRandom()` — adequate on modern JVMs |

---

### [CRY-001] Control NULL / password AUTHENTICATE fail-open
- **Track**: crypto
- **Evidence**:
  - `control/.../ControlServer.kt:257-266` — `METHODS=NULL` when `cookieAuthentication` off and `hashedControlPassword` blank
  - `:279-284` — empty `AUTHENTICATE` → `authenticated = true`
  - `:296-299` — quoted password accepted whenever hash unset and cookie off (any string)
  - `:346-350` — hex blob path same NULL grant
  - Default config still prefers cookie (`TorConfig.kt:13` `cookieAuthentication = true`); fail-open only when operator disables both
- **Risk**: High (Critical if ControlPort non-loopback — IO-005 / FAIL-004)
- **Exploit logic**: Attacker reaches Control → `AUTHENTICATE` / `AUTHENTICATE "x"` → full `SIGNAL`/`SETCONF`/`ADD_ONION`
- **Fix**: Refuse non-loopback Control without cookie or hashed password; optionally refuse NULL entirely outside test builds. Keep SAFECOOKIE/COOKIE fail-closed paths as-is
- **Related**: FAIL-004, IO-005, IO-006

### [CRY-002] Handshake AUTH / MAC / KH use non-constant-time compare
- **Track**: crypto
- **Evidence**:
  - `crypto/Ntor.kt:64` — `expectedAuth.contentEquals(auth)`
  - `crypto/NtorV3.kt:135`, `:205` — AUTH and client MAC
  - `crypto/CreateFast.kt:34` — KH wire check
  - `hs/HsNtor.kt:136`, `:182` — hs-ntor AUTH / INTRODUCE2 MAC
  - Control path already fixed: `ControlServer.kt:316,329` + `ControlS2k.kt:55` use `constantTimeEquals`
- **Risk**: High (remote timing on circuit/HS handshakes; local control was Medium and is largely mitigated)
- **Fix**: Replace AUTH/MAC/KH secret compares with `constantTimeEquals` (same helper as control). Keep public ID/KEYID checks as-is or constant-time for uniformity
- **Related**: CRY-007 (control positive), FAIL auth

### [CRY-003] Ephemeral secrets survive handshake without wipe
- **Track**: crypto
- **Evidence**:
  - `Ntor.kt:68-70` wipes `secretXy`/`secretXb`/`secretInput` but **not** `state.secretKey`, HKDF `keys` buffer, or `Result.keySeed`
  - `NtorV3.kt:108-141` — `yx`, `bx` (also retained on `ClientState`), `secretInput`, `clientSk` never wiped
  - `HsNtor.kt:125-137`, `:174-189` — shared secrets / seed material uncleared
  - `CreateFast.kt` / `CreateOnehop.kt` — client `x` and seed material retained for GC only
  - Contrast: `NtorServer.kt:32-34` matches client wipe of DH products only
- **Risk**: High (heap dumps / swap / crash cores retain circuit/HS keying material)
- **Fix**: After successful finish (and on failure paths): wipe ephemeral sk, DH outputs, seeds, and intermediate HKDF buffers; clear `ClientState` fields; document that live hop keys in `HopCrypto`/`CgoHop` remain until circuit close (then wipe — CRY-005)
- **Related**: CRY-005, MEM hop lifetime

### [CRY-004] CreateFast still available (client + relay always-on)
- **Track**: crypto
- **Evidence**:
  - `crypto/CreateFast.kt` — SHA1 KDF-TOR; no DH (X‖Y over OR TLS)
  - `circuit/Circuit.kt:205-219` `createFirstHopFast`; `:933-937` used when `useCreateOnehop=false`
  - `relay/RelayService.kt:482-488`, `:854-867` handles `CREATE_FAST` unconditionally
  - `relay/RelayConfigFindAddr.kt:251` `supportsCreateFast(...) = true`
- **Risk**: Medium (legacy one-hop dir; weaker than ntor if OR TLS/logs compromised; relay cannot refuse)
- **Fix**: Prefer CreateOnehop/ntor for dir circuits; gate relay `CREATE_FAST` behind config/consensus (mirror C Tor); document residual use; fail closed on EXTEND carrying CreateFast
- **Related**: deferred disable; CreateOnehop prop364 also non-DH but stronger KDF

### [CRY-005] `secureWipe` + AES-CTR/CGO key destroy gaps
- **Track**: crypto
- **Evidence**:
  - `util/Bytes.kt:18-20` — `secureWipe()` only `fill(0)` (no native mlock/Cleaner; copies/`copyOfRange` untouched)
  - `crypto/AesCtr.kt:11-18` — `KeyParameter(key)` into BC SIC engine; no `destroy`/wipe of key or cipher state
  - `circuit/CircuitCrypto.kt:47-48` — hop ciphers hold keys for circuit life with no close wipe
  - `crypto/CgoHop.kt:19-33` — rotatable `keys`/`nonce` arrays; no wipe on hop teardown; recognition still `contentEquals` (`:65`, `:83`)
  - `Cgo.kt` ET/PRF copy `kb`/`ku`/`k` slices without wipe after use
- **Risk**: Medium (defense-in-depth; amplifies CRY-003)
- **Fix**: Wipe hop/CGO key arrays on circuit close; optional AesCtr.close() zeroing; treat wipe as best-effort but call it consistently; use constant-time compare for CGO nonce recognition if side channels matter
- **Related**: CRY-003

### [CRY-006] Control cookie bytes linger; length not enforced
- **Track**: crypto
- **Evidence**:
  - `TorDaemon.kt:153-155` — `SecureRandomSource.nextBytes(32)` then `Files.write`; in-memory `cookie` never `secureWipe`
  - `ControlServer.kt:245-248`, `:327-329` — `Files.readAllBytes` for SAFECOOKIE/COOKIE; no `cookie.size == ControlCookie.COOKIE_LEN` (32)
  - Truncated/overlong cookie file → weak or length-leaking compare (`constantTimeEquals` early size exit at `Bytes.kt:26`)
- **Risk**: Medium
- **Fix**: Enforce 32-byte cookie on write and read (fail closed); wipe buffers after HMAC; pair with IO-006 `0600` / CookieAuthFile
- **Related**: IO-006, CRY-001, CRY-007

### [CRY-007] Control secret compares already constant-time (positive)
- **Track**: crypto
- **Evidence**: `ControlServer.kt:316` SAFECOOKIE ClientHash; `:329` COOKIE; `ControlS2k.kt:55` HashedControlPassword; helper `util/Bytes.kt:22-31`
- **Risk**: Low (mitigated for control auth material)
- **Fix**: None for control; extend pattern to CRY-002 wire handshakes
- **Related**: CRY-002

### [CRY-008] SecureRandom usage for crypto material (ok / residual)
- **Track**: crypto
- **Evidence**:
  - Handshake/cookie/padding: `SecureRandomSource` (`Bytes.kt:72-76`) — shared `SecureRandom()`
  - `Curve25519.generateKeyPair`, `CreateFast`/`CreateOnehop` X/Y, `ControlS2k` salt, `TorDaemon` cookie, `OrAuthenticate` rand
  - TLS: `TorSsl.kt:37` / `OrCertMaterial` pass `SecureRandom()` into `SSLContext.init`
  - Non-crypto: `WebSocketFrame.kt:32` per-call `SecureRandom()` for masks only
- **Risk**: Low on Linux/Android default providers; residual if a JVM substitutes a weak `SecureRandom` SPI
- **Fix**: Optional `SecureRandom.getInstanceStrong()` (or explicit NativePRNG) for `SecureRandomSource` only; keep single process-wide instance
- **Related**: —


## buffer


**Scope:** MTU/cell receive buffers, `ByteArray`/`StringBuilder` growth, UnparseableDump, directory document assembly, stream RELAY DATA coalescing.  
**Main sources:** `:core` (`cell`, `circuit`, `link`, `dir`, `compress`, `net/stack`, `relay`), `:proxy` (`DnsPortServer`).

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| BUF-003 | **High** | BEGIN_DIR `StringBuilder` appends RELAY DATA with no size cap until headers end |
| BUF-004 | **High** | Stream inbound `Channel.UNLIMITED` + one-cell `read()` — no DATA coalesce / backpressure |
| BUF-005 | **High** | `TorCompress.uncompress` / dir inflate grow unbounded; `isCompressionBomb` unused |

---

### [BUF-001] DNSPort shared receive buffer copy (safe)
- **Track**: buffer
- **Evidence**: `proxy/.../DnsPortServer.kt:48-56` — single `ByteArray(512)` for `DatagramPacket`; `packet.data.copyOf(packet.length)` before `launch { handleQuery }`
- **Risk**: Low
- **Fix**: None required; keep copy-before-launch pattern on any shared UDP buf
- **Related**: IO-003, BND-002

### [BUF-002] UnparseableDump body capped; tag map not
- **Track**: buffer
- **Evidence**: `core/.../dir/DirParseHelpers.kt:73-86` — `dumps[tag] = body.take(64_000)` into unbounded `ConcurrentHashMap`; production `note()` mostly tests today
- **Risk**: Medium
- **Fix**: Cap tag count (LRU/FIFO, e.g. 64); reject empty/oversized tags; keep 64KB body cap
- **Related**: MEM map-cap pattern; SAFETY_AUDIT deferred “UnparseableDump caps”

### [BUF-003] BEGIN_DIR stream `StringBuilder` unbounded
- **Track**: buffer
- **Evidence**: `relay/RelayService.kt:371-373` `DirStreamState(buf: StringBuilder)`; `:570-576` every `RELAY DATA` does `ds.buf.append(...)` until `\r\n\r\n` / `\n\n` — no max length. Contrast DirPort HTTP path `:304` (`headerBytes` hard-stop 65536)
- **Risk**: High (relay ORDir path DoS)
- **Fix**: Cap `ds.buf.length` (e.g. 64KiB headers); END/DESTROY stream and drop on overflow; prefer `ByteArrayOutputStream` + length check over unbounded `StringBuilder`
- **Related**: BUF-002 (64KB diagnostic theme), MEM

### [BUF-004] Stream DATA: unlimited channel, no coalescing
- **Track**: buffer
- **Evidence**:
  - `circuit/Circuit.kt:391,410,463,605` — per-stream `Channel<RelayCell>(Channel.UNLIMITED)`
  - `:150-158` inbound DATA `ch.send(relay)` with no queue bound
  - `TorStream.read()` `:721-729` returns **one** DATA cell; no merge of consecutive DATA
  - Outbound `sendData` `:642-649` correctly chunks at 498; inbound is the gap
- **Risk**: High
- **Fix**: Bounded stream inbuf (bytes and/or cells) with SENDME/backpressure; coalesce adjacent DATA into a growable buf with hard max before delivering to `read()` / `BytePipe`
- **Related**: CircuitFlowControl / CongestionControl (window ≠ channel bound); MEM; IO stream close

### [BUF-005] Inflate / uncompress ByteArray growth uncapped
- **Track**: buffer
- **Evidence**: `compress/TorCompress.kt:113-127` `GZIPInputStream`/`InflaterInputStream` `.use { it.readBytes() }`; `isCompressionBomb` `:140-143` exists but is **never called**. `dir/DirectoryClient.kt:185-193` `httpGet` → `readBytes()` then `maybeInflate` → `readText()` with no output ceiling
- **Risk**: High
- **Fix**: Stream decompress into a capped buffer; refuse when `isCompressionBomb(in, out)` or out > consensus-size budget (e.g. 16–64 MiB); apply same gate to Zstd/LZMA providers
- **Related**: MEM, dir fetch path

### [BUF-006] TUN MTU buffer silent truncation
- **Track**: buffer
- **Evidence**: `net/stack/TunTorBridge.kt:62,77-88` — single `ByteArray(mtu.coerceAtLeast(1500)+64)` reused; `MemoryTun.readPacket` `:109-112` `arraycopy(..., pkt.size.coerceAtMost(buf.size))` returns truncated length without error if device/test injects > MTU
- **Risk**: Medium
- **Fix**: Drop/log when `n > buf.size` or `pkt.size > buf.size`; size TUN buf from negotiated MTU; never silently shrink IP packets
- **Related**: OnionTunnel `mtu` default 1500; BND

### [BUF-007] Cell / channel ByteArray `copyOf` amplification
- **Track**: buffer
- **Evidence**: `circuit/CircuitMux.kt:12-15` `CellQueue.append` → `payload.copyOf()` up to `DEFAULT_MAX=1024` cells/circ; `link/OrChannel.kt:80-84` `queueOut` copies under `MAX_OUTBUF` 32 MiB; `appendIn` `:110-114` copies with **no** inbuf cap (lite path / tests)
- **Risk**: Medium
- **Fix**: Keep per-circ cell cap; lower default `MAX_OUTBUF` for embed; add `MAX_INBUF` mirroring outbuf; avoid double-copy where ownership transfers
- **Related**: MEM-003, KIST flush budget (`KistCmuxLoad` 514-byte cells)

### [BUF-008] `readHttpResponse` boxes every byte + rebuilds String
- **Track**: buffer
- **Evidence**: `circuit/Circuit.kt:733-755` — `ArrayList<Byte>()` then `for (b in chunk) out += b`; each iteration `out.toByteArray().decodeToString()` to find headers / Content-Length. Cap `maxBytes` default 512 KiB mitigates absolute size but not O(n²) copies / boxing
- **Risk**: Medium
- **Fix**: `ByteArrayOutputStream` (or single `ByteArray` + length); parse headers once; stop copying full body into `String` until complete
- **Related**: BUF-004 (caller of per-cell `read()`)


## null


Scope: main Kotlin (`core` / `proxy` / `control` / `android` / `cli`). Focus: NPE on optional hop keys, consensus null, port `-1` / zero-port misuse, `!!`, nullable config on hot paths. Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| NUL-001 | High | Optional hop `ed25519Identity` → silent ntor-v3 downgrade / incomplete EXTEND linkspecs |
| NUL-002 | High | `hopKeys[fp]!!` after `ensureHopKeys` (NPE if cache eviction / map race) |
| NUL-003 | High | Nullable `consensus` read off-mutex; HS manager wired to `consensusOrNull()` |
| NUL-004 | High | Port `-1` sentinels (engine getters + `protect(-1)`) treated as usable FDs/ports |
| NUL-005 | High | HSDir HTTP fetch uses consensus `dirPort` (often `0`) → `host:0` URLs |
| NUL-006 | High | `OrConnection` `input!!`/`output!!`/`socket!!` on OR send/read/handshake |
| NUL-007 | High | Nullable `orPort`/`dirPort`/`address` → fabricated listen/publish defaults |
| NUL-008 | High | Partial-start leaves non-null listener refs while siblings failed |

No Critical-only null finding beyond overlaps with **RET-001** / **FAIL-001** (partial start); strongest standalone null risks are High.

---

### [NUL-001] Optional hop ed25519 / ntor keys silently degrade CREATE/EXTEND
- **Track**: null
- **Evidence**: `core/.../circuit/Circuit.kt:25-28` (`HopKeys.ed25519Identity` nullable); `:193-199` / `:287-298` (use `keys.ed25519Identity ?: router.ed25519Identity`; if both null and `supportsNtorV3()`, fall through to classic ntor without ed linkspec); `dir/DescriptorParser.kt:5-6,57` (ed optional); `dir/Consensus.kt:37-38` (`RouterStatus.ntorOnionKey` / `ed25519Identity` nullable); `hs/OnionClient.kt:145,164-165`; `hs/OnionService.kt:342` (rend hop may lack ed)
- **Risk**: High
- **Fix**: Fail closed when Relay≥4 path needs ed but identity missing; never silently omit LSTYPE=3; treat missing ntor onion key as hard error before dial (do not build `ExtendInfo` with null `curve25519OnionKey` for multi-hop)
- **Related**: TYP-002, CRY (handshake), MEM-002 (key cache)

### [NUL-002] `hopKeys[fp]!!` after ensure on client / HS ensure callback
- **Track**: null
- **Evidence**: `core/.../TorClient.kt:107-109` (`ensureHopKeys` then `hopKeys[fp]!!` for `OnionClient`); `:372-379` (`ensureHopKeys` puts under `fp`, but may accept `docs.values.firstOrNull()` when FP mismatch); `:414-416` (`hopKeysFor` → `!!`)
- **Risk**: High (NPE once hopKeys eviction / concurrent clear lands; wrong-descriptor put still leaves `!!` “succeeding” with stale semantics)
- **Fix**: Make `ensureHopKeys` return `HopKeys`; drop `!!`; refuse descriptor whose fingerprint ≠ requested `fp`
- **Related**: TYP-002, MEM-002, CF-003

### [NUL-003] Nullable consensus on hot path / HS wiring
- **Track**: null
- **Evidence**: `TorClient.kt:95` (`private var consensus: Consensus? = null`); `:217` (onion `connect` reads under `mutex`); `:290`, `:307`, `:321+` (`circuitForIsolation` / descriptor APIs read `consensus` **without** mutex); `:408` (`consensusOrNull()`); `TorDaemon.kt:258` (`onionServices.consensus = { client.consensusOrNull() }`); `hs/OnionService.kt:132-133`, `:177`, `:250`, `:410` (`consensus?.invoke() ?: error(...)`); `:259` (`HsDosDefense.applyConsensus(consensus?.invoke())` — null no-ops DoS param refresh)
- **Risk**: High
- **Fix**: Single mutex-/atomic snapshot for all consensus reads; HS `startAll` must await bootstrap (non-null consensus) before intro/publish; pass `Consensus` not `Consensus?` into DoS apply after gate
- **Related**: CF-003, FAIL (bootstrap ordering)

### [NUL-004] Port / FD `-1` sentinel misuse
- **Track**: null
- **Evidence**: `android/.../KotlinTorEngine.kt:55-60` (`socksPort`/`dnsPortBound`/`controlPort`/… → `-1` when unbound); `os/PlatformNatives.kt:222-234` (`protectSocket` calls `protector(-1)` when FD unavailable, returns `false`); `config/TorConfig.kt:340-348` (`ListenSpec.parse` → `toInt()` accepts negative port strings); `dir/DescriptorPublisher.kt:39` / `DirAuthVoteGossip.kt:149` (HTTP `code = -1` on I/O error — sentinel overload)
- **Risk**: High (UI/VPN may dial or `VpnService.protect(-1)`; negative ListenSpec binds fail oddly or confuse callers)
- **Fix**: Prefer `Int?` / `boundPortOrNull()`; never pass `-1` to protect (no-op + fail-closed dial — align RET-002); reject `port <= 0` in `ListenSpec.parse` except documented `auto`/`0`; keep HTTP error code separate from listen ports
- **Related**: RET-002, MEM-006, demo-ui (prior NUL-001)

### [NUL-005] Consensus `dirPort == 0` used as HTTP directory URL
- **Track**: null
- **Evidence**: `hs/HsDirClient.kt:118-120` (`http://${dir.ip}:${dir.dirPort}/tor/hs/3/$id` for every selected HSDir); `dir/Consensus.kt:31-32` (`dirPort: Int` — commonly `0` when relay has no DirPort); clearnet dir clients similarly: `DirectoryClient.kt:39+`, `DescriptorPublisher.kt:21`
- **Risk**: High (HS descriptor fetch attempts `*:0`, burns timeouts, weakens HS availability)
- **Fix**: Skip relays with `dirPort <= 0` for HTTP dir; use BEGIN_DIR over ORPort when DirPort absent (C Tor path); assert `port in 1..65535` before URL build
- **Related**: IO (clearnet dir), HS client path

### [NUL-006] `OrConnection` force-unwraps nullable socket streams
- **Track**: null
- **Evidence**: `link/OrConnection.kt:60-62` (`socket`/`input`/`output` nullable); `:228` (`CellCodec.read(input!!, …)` handshake); `:341` (`socket!!.localAddress` NETINFO); `:363` (read loop `input!!`); `:425-426`, `:480-481` (`output!!.write` / `flush`)
- **Risk**: High (NPE crash on OR hot path if send/read after close, failed connect, or racing `stop`)
- **Fix**: Local non-null vals after successful `connect`; `send`/`readLoop` check `isOpen` and return/throw typed closed error; null fields under write mutex on close
- **Related**: IO-007, CF cancel/teardown, RET-001

### [NUL-007] Nullable listen/config fields on daemon & relay publish path
- **Track**: null
- **Evidence**: `config/TorConfig.kt:20-23`, `:67` (`orPort`/`dirPort`/`metricsPort`/`address` nullable); `TorDaemon.kt:270-271` (`dirPort?.host ?: "127.0.0.1"`, `dirPort?.port ?: 9030` when minting authority cert — fabricates DirPort); `relay/RelayService.kt:191-197` (`orPort ?: return`; `dirPort?.port ?: 0` written into descriptor); `:229-234` (similar); `pt/PtServerManager.kt:37` (`config.orPort ?: config.extOrPort`)
- **Risk**: High (mis-published OR/Dir endpoints; dirauth cert lies about listen; PT may start with null OR)
- **Fix**: Require explicit `ORPort`/`DirPort` before auth/relay publish; no silent `9030`; treat missing address as config error not `127.0.0.1`
- **Related**: IO-005 bind policy, FAIL config validation

### [NUL-008] Partial-start leaves inconsistent non-null listener refs
- **Track**: null
- **Evidence**: `android/.../KotlinTorEngine.kt:99-143` (`running=true` then sequential assigns to `socks` / `roleSocks` / `dnsPort` / …); failure path historically cleared `running` without nulling already-started listeners (see RET-001)
- **Risk**: High
- **Fix**: Covered by RET-001 teardown — clear **all** listener refs to null and stop siblings before `onError`
- **Related**: RET-001, FAIL-001, CF-001, MEM-006/007

---


## integer


**Scope:** main Kotlin sources (`core/`, `proxy/`, `control/`, `android/`).  
**Focus:** signed-byte masking, bandwidth/TTL/seq overflow, CircId wrap, port `Int` overflow, `u16be`/`u32be` misuse.  
**Cap:** 8 · **Severity filter:** Critical / High only.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| INT-001 | Critical | `u16be`/`u32be` silently truncate; variable-cell & handshake lengths can lie on the wire |
| INT-002 | High | `newCircId()` never retries; `registerCircuit` overwrites on collision |
| INT-003 | High | Origin `nextStreamId++` unbounded; relay encodes only u16 → alias / map skew |
| INT-004 | High | Ports parsed/encoded as unbounded `Int` (`toInt` / `toShort` / `u16be`) |
| INT-005 | High | `parseBandwidth` Long wrap; `bandwidthKb.toInt()` advertise truncate |
| INT-006 | High | `EdgeConnectionTable` keys mask streamId to u16 while Circuit uses full `Int` |
| INT-007 | High | DNS A-record octets `toInt().toByte()` wrap without 0..255 check |
| INT-008 | High | Conflux `nextSeq++` / TCP seq: u32 wrap OK in TUN; conflux relies on signed `Long` wrap |

---

### [INT-001] Silent truncation in `u16be` / `u32be`
- **Track**: integer
- **Evidence**: `core/.../util/Bytes.kt:44-48` (`u16be` takes low 16 bits only; `u32be` → `putInt(value.toInt())`); `cell/Cell.kt:41` `u16be(cell.payload.size)` for variable cells; `relay/RelayService.kt:927,971,998,1072` `u16be(handshake/response.size)`
- **Risk**: Critical
- **Fix**: Require `value in 0..0xffff` / `0L..0xffff_ffffL` (or return `Result`); refuse encode when size > field width; prefer checked helpers (`requireU16`, `requireU32`) at every call site that writes wire lengths
- **Related**: BUF variable-cell, bounds on CREATED2/EXTENDED2

### [INT-002] CircId allocate without uniqueness
- **Track**: integer
- **Evidence**: `link/OrConnection.kt:530-536` (`newCircId` random \| `0x80000000`); `OrConnection.kt:111-116` `registerCircuit` assigns `circuitChannels[circId] = ch` with no prior-occupancy check
- **Risk**: High
- **Fix**: Retry until free (and ≠ 0); reject inbound CREATE if circId already mapped; treat wrap/collision as protocol error not silent replace
- **Related**: CircuitMux.attach same id, relay CircState maps

### [INT-003] Origin streamId overflows u16 wire field
- **Track**: integer
- **Evidence**: `circuit/Circuit.kt:39` `private var nextStreamId = 1`; `:390,409,462` `nextStreamId++`; `cell/Cell.kt:93-94,99` streamId packed as two bytes
- **Risk**: High
- **Fix**: Allocate with `AtomicInteger` and `and 0xffff`, skip 0, refuse at open streams; refuse new streams when space exhausted (mirror `EdgeConnectionTable.allocStreamId`)
- **Related**: INT-006, RELAY BEGIN/DATA demux

### [INT-004] Port `Int` overflow / no 0..65535 gate
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:345-347` `ListenSpec.parse` `toInt()`; `:675` `HiddenServicePort(vp[0].toInt(), …)`; `circuit/CircuitCrypto.kt:277-278` `parseBeginPayload` `toInt()`; `net/NetworkPolicy.kt:94-97` exit-policy ports; `net/SocksCodec.kt:103-115` `putShort(e.port.toShort())`; `hs/LinkSpecifiers.kt:23` `u16be(relay.orPort)`
- **Risk**: High
- **Fix**: Single `requirePort(p: Int): Int` (`p in 0..65535`, or `1..65535` where 0 disallowed); use at parse and before `toShort`/`u16be`
- **Related**: IO bind, BEGIN exit, HS virtual port

### [INT-005] Bandwidth unit multiply wrap + advertise `toInt`
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:399-409` `n * 1_000_000_000` etc. (Kotlin `Long` wraps); `relay/RelayService.kt:236` `(bandwidthRateBytes / 1000).toInt().coerceAtLeast(1)`
- **Risk**: High
- **Fix**: `Math.multiplyExact` / checked parse with cap (e.g. `Long.MAX_VALUE / unit`); advertise with `coerceAtMost(Int.MAX_VALUE.toLong()).toInt()` only after documenting dir-spec KB/s ceiling; reject absurd torrc values
- **Related**: descriptor `bandwidth` line, BridgeAuth `w Bandwidth=`

### [INT-006] Edge stream key masks u16; Circuit does not
- **Track**: integer
- **Evidence**: `circuit/ConnectionEdge.kt:36-37,50` `key = (circId shl 16) or (streamId and 0xffff)`; `Circuit.kt:390-393` opens edge with unmasked `nextStreamId++`
- **Risk**: High
- **Fix**: One allocator (`allocStreamId`) for origin and edge table; assert `streamId in 1..0xffff` at `open`/`get`
- **Related**: INT-003

### [INT-007] DNS A-record octet wrap (signed / out-of-range)
- **Track**: integer
- **Evidence**: `proxy/.../DnsPortServer.kt:134` `out.put(p.toInt().toByte())` — no `0..255`; contrast masked reads at `:94,109,117`
- **Risk**: High (malformed / attacker-controlled name→A path emits wrong addresses)
- **Fix**: Parse octet with range check; reject answer or skip RR if any part ∉ 0..255; keep `and 0xff` on all byte→int reads (already good on query path)
- **Related**: BND-001, FakeIp / Automap string IPs

### [INT-008] Seq counters: Conflux Long vs TCP u32 mask
- **Track**: integer
- **Evidence**: `circuit/Conflux.kt:16-24` `nextSeq++` then `u64be` (`Bytes.kt:50-51`); TUN path `net/stack/TunIpStack.kt:141,148,171` uses `and 0xffffffffL` (correct u32); `net/TcpDns.kt:69-70` `putInt(seq.toInt())` relies on caller masking
- **Risk**: High if any caller feeds unmasked seq > u32 into `TcpHeader.build`; Conflux signed overflow is bit-preserving for u64 but lacks explicit modular API / tests
- **Fix**: `fun u32(seq: Long) = seq and 0xffffffffL` at TCP build boundary; Conflux `nextSequence()` document + test wrap at `ULong` semantics; never pass raw wall TTL ms into u16/u32 fields without coerce
- **Related**: RESOLVED TTL fixed 60s (`RelayService.kt:698-705`) — low risk; HsCache TTL uses `Long` (`HsCache.kt:17,100`) — OK

---


## failure


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


## controlflow

# Control-flow domain audit (CF)

**Repo:** kotlin-tor · **Scope:** main sources (`core/`, `android/`, `control/`)  
**Focus:** OR handshake FSM, HS intro FSM, dormant gate, `ConcurrentHashMap` TOCTOU, `KotlinTorEngine.running`, stop↔start races  
**Cap:** 8 findings · **Risk filter:** Critical / High only

## Critical / High summary

| ID | Risk | One-line |
|----|------|----------|
| [CF-001] | Critical | OR link handshake is flag soup, not an FSM; completes without CERTS and skips identity check when fingerprint is null |
| [CF-002] | Critical | `KotlinTorEngine.stop` vs `startWithPorts` race on `running` + cancelled `scope` leaves partial listeners / double lifecycle |
| [CF-003] | High | HS intro `HsIntroFsm` is bookkeeping only; INTRODUCE2 path never gates on ESTABLISHED |
| [CF-004] | High | `HsIntroPointTable` stores mutable FSM cells in `ConcurrentHashMap` (lost updates / stale CLOSED) |
| [CF-005] | High | `ReplayCache.addAndTest` horizon refresh is non-atomic → dual INTRODUCE2 accept after TTL |
| [CF-006] | High | `TorDaemon.stop` / `start` TOCTOU on `started` AtomicBoolean (no CAS teardown) |
| [CF-007] | High | Soft dormant: check-then-act on `@Volatile dormant` allows streams after DORMANT |
| [CF-008] | High | Cross-map CHM TOCTOU: Keypin check-then-add, Fake-IP allocate, HsCache `allocatedBytes` |

---

### [CF-001] OR handshake lacks ordered FSM; CERTS optional for open
- **Track**: controlflow
- **Evidence**: `core/.../link/OrConnection.kt:218-283` (`performHandshake`); `:182-188` (identity gate); `core/.../or/OrStructMirrors.kt:193-199` (`OrHandshakeState` unused by live path); relay peer: `core/.../relay/RelayService.kt:426-446`
- **Risk**: Critical
- **Exploit logic**: Peer sends VERSIONS + NETINFO and omits CERTS. Handshake loop exits on `sawVersions && sawNetinfo`. Caller passes `expectedIdentityHex`, but check is `if (peer != null && !peer.equals(...))` — null peer skips mismatch. Client opens OR to attacker without link identity.
- **Fix**: Drive a real state machine (VERSIONS → CERTS required → optional AUTH_CHALLENGE → NETINFO). Reject out-of-order / duplicate cells. Fail connect if CERTS missing or fingerprint ≠ expected. Wire or delete unused `OrHandshakeState`.
- **Related**: Circuit EXTEND uses `connect(expectedIdentityHex=…)` (`Circuit.kt`); relay acceptor also advances to CREATE2 without inbound CERTS FSM.

### [CF-002] `KotlinTorEngine` stop↔start race on `running`
- **Track**: controlflow
- **Evidence**: `android/.../KotlinTorEngine.kt:99-144` (CAS true then async start); `:147-158` (`stop`: `if (!running.get()) return` … `scope.cancel()` … `running.set(false)`)
- **Risk**: Critical
- **Exploit logic**: Thread A `startWithPorts` CAS→true and launches bind work. Thread B `stop` sees true, cancels `scope` (aborts bind), nulls servers, sets `running=false`. Thread C starts again while A’s late assignments still write `socks`/`control`, or stop tears down mid-`daemon.start()`. `stop` never CAS-claims ownership; concurrent stops double-`scope.cancel`.
- **Fix**: Single lifecycle mutex or state enum (`IDLE|STARTING|RUNNING|STOPPING`). `stop` must `compareAndSet(true,false)` (or CAS STARTING→STOPPING) before teardown; await start job; disallow re-start until fully idle. Do not cancel a shared scope that outlives one start cycle without recreating it.
- **Related**: [CF-006] TorDaemon; `OnionTunnel` uses safer `getAndSet(false)` (`OnionTunnel.kt:74-78`).

### [CF-003] HS intro FSM not a control gate for INTRODUCE2
- **Track**: controlflow
- **Evidence**: FSM enum `core/.../hs/HsCommonConfigDos.kt:155-161`; transitions `:176-209`; live use `OnionService.kt:195-199` (`beginEstablish`/`noteEstablished`), `:266` (`noteIntroduce` after DoS admit), `:242-307` (`handleIntroduce2` never reads `fsm`)
- **Risk**: High
- **Exploit logic**: `noteIntroduce` only mutates counters/FSM if entry exists; it does **not** reject CLOSED/ESTABLISHING/NONE. `handleIntroduce2` proceeds to decrypt/rendezvous regardless. FSM can sit ESTABLISHING forever if `establishIntro` throws after `beginEstablish` (no `noteClosed` on that failure path `:208-209`), yet a late cell on a reused circuit could still be handled via `IntroPointLive` list.
- **Fix**: Enforce allowlist transitions; `handleIntroduce2` must require `fsm ∈ {ESTABLISHED, INTRO_RECEIVED}`. On establish failure call `noteClosed`. Refuse INTRODUCE2 when table says CLOSED.
- **Related**: [CF-004], [CF-005].

### [CF-004] Mutable intro state in ConcurrentHashMap (FSM TOCTOU)
- **Track**: controlflow
- **Evidence**: `HsCommonConfigDos.kt:173-209` (`byAuth: ConcurrentHashMap<String, HsIntroPointState>` with `var fsm` / `var introduceCount`); `beginEstablish` unconditional `byAuth[k] = st` overwrite
- **Risk**: High
- **Exploit logic**: Map ops are atomic per key, but field updates are racy. Concurrent `noteIntroduce` / `noteClosed` can lose increments or leave `established=true` with `fsm=CLOSED`. `beginEstablish` replaces ESTABLISHED entry without transition check → listeners still on old circuit while table points at new ESTABLISHING key.
- **Fix**: Immutable state snapshots via `compute`/`merge`, or per-key lock; CAS transition helper `transition(from, to)`. Never overwrite ESTABLISHED without CLOSE first.
- **Related**: [CF-003]; same pattern `HsCache.IntroState` (`HsCache.kt:34-39`, `:112-119`).

### [CF-005] ReplayCache horizon refresh race (dual accept)
- **Track**: controlflow
- **Evidence**: `core/.../hs/ReplayCache.kt:24-33`; call site `OnionService.kt:305-307`
- **Risk**: High
- **Exploit logic**: After `putIfAbsent` hits aged entry, code non-atomically `seen[key] = now` and returns non-replay. Two threads observing the same expired digest both refresh and both return `false` → two INTRODUCE2 with identical ENCRYPTED decrypt and launch rendezvous.
- **Fix**: `compute(key) { … }` returning replay boolean in one map op; or `replace(key, prev, now)` and treat failed replace as replay.
- **Related**: [CF-003] intro path ordering (replay after DoS/metrics already incremented).

### [CF-006] TorDaemon `started` stop without ownership CAS
- **Track**: controlflow
- **Evidence**: `TorDaemon.kt:135-136` (`compareAndSet(false,true)` on start); `:329-340` (`if (!started.get()) return` then tear down, `started.set(false)` last)
- **Risk**: High
- **Exploit logic**: Start holds CAS; stop only reads then clears. Concurrent `stop` while `start` still in `client.bootstrap()` cancels `scope` under the starter; starter may throw or partially wire HS/relay, then `started=false` allows a second `start` overlapping teardown. Control `SIGNAL DORMANT` (`ControlServer.kt:482-483`) can interleave with stop.
- **Fix**: Mirror engine fix: lifecycle enum + CAS on stop; `start` must not leave `started=true` if bootstrap aborted by cancel; join child jobs before clearing flag.
- **Related**: [CF-002], [CF-007].

### [CF-007] Dormant check-then-act (soft gate TOCTOU)
- **Track**: controlflow
- **Evidence**: `TorClient.kt:186` (`if (dormant) error`) then work; `:400-406` (`@Volatile var dormant`); `OnionTunnel.kt:87-88` + `:167-175` (scaffolding + `setDormant`); control `SIGNAL DORMANT`/`ACTIVE`
- **Risk**: High
- **Exploit logic**: Thread observes `dormant==false`, opens stream; concurrent `signalDormant()` sets true — stream still builds circuits. Inverse: ACTIVE then DORMANT around the check admits a stream under “dormant” policy. OnionTunnel checks scaffolding dormant separately from `TorClient.dormant` → split-brain if only one side updated.
- **Fix**: Treat dormant as generation counter or require `mutex` with connect; refuse under single atomic read at circuit allocation. Document that soft dormant does not tear down existing streams (if intentional, enforce only at one choke point).
- **Related**: [CF-006]; OnionTunnel comment on polarity hazard `:172`.

### [CF-008] ConcurrentHashMap check-then-act clusters
- **Track**: controlflow
- **Evidence**:
  - Keypin: `KeypinAndConsDiff.kt:36-54` (`check` then `byRsa`/`byEd` puts — two conflicting pairs can both ADD)
  - Fake-IP: `FakeIpDnsCookies.kt:41-58` (lookup / `containsKey` then insert — duplicate cookie or host remap)
  - HsCache: `HsCache.kt:45-55`, `:143-151` (non-atomic `allocatedBytes` with CHM entries)
- **Risk**: High
- **Exploit logic**: Classic TOCTOU: observation and mutation are separate. Dirauth keypin can pin inconsistent RSA↔Ed maps; VPN fake-IP can hand two hosts the same cookie or orphan reverse entries; cache accounting drifts → bad OOM trim decisions.
- **Fix**: `compute`/`putIfAbsent` with conflict return; dual-map Keypin under one lock or single composite key; `AtomicLong` for `allocatedBytes` updated inside map compute.
- **Related**: [CF-004], [CF-005].

---

## Out of scope / deferred (not counted)

- Circpad / Conflux FSMs, guard reachability FSM — not in this focus pass.
- Medium: `RelayService.@Volatile running` loop races; `OnionServiceManager.running` unsynchronized list.

## Conflicts

### From memory

Cross-checks against other `docs/safety/domains/*.md` likely fixes:

| Clash | Domains | Note |
| --- | --- | --- |
| Accept semaphore vs ConnectionTable cap | IO-001..004, MEM-003 | Prefer **both**: fail-closed refuse at accept (IO) **and** ConnLimit on `ConnectionTable.add` (MEM). Do not rely on table-only rejection after spawn. |
| Fake-IP atomic insert vs eviction | CF-002, MEM-001 | `compute`/`putIfAbsent` (CF) must compose with hard-cap eviction (MEM); eviction must update both IP↔host maps atomically. |
| isolatedCircuits mutex vs LRU close | CF-003, MEM-002, MEM-005 | Eviction/close must run under same `mutex` as `circuitForIsolation`; closing must also scrub `CircuitList`/`open` (MEM-005) or CF “safe” map still leaks. |
| Engine `scope.cancel` vs restart | CF-001, RET Conflicts, MEM-007 | CF/RET prefer recreating scope for restart UX; MEM agrees — do **not** keep cancelled root. Clearing `PlatformNatives.socketProtector` (MEM-006) must land in same teardown as RET-001. |
| Cap sizes vs throughput | CPU-001 Conflicts, IO Conflicts, prior MEM stub | Fail-closed reject/drop under load; do not raise caps to “fix” stress tests. |
| UnparseableDump tag growth | BUF-002 | Per-body `take(64_000)` exists (`DirParseHelpers.kt:77`); tag count still unbounded — BUF size cap should include max tags (align with MEM map-cap pattern). |
| HsCache model | (supersedes prior MEM-004 “already capped”) | Dir/client entry trim is real; intro/dirConn + unscheduled `cleanAs*` remain MEM issues — do not treat HsCache as fully bounded. |

### From io
- **IO-001/002/003/004 vs CPU-001 / MEM-003 / FAIL-004**: Aligned — prefer fail-closed close/drop over queue-wait under load (do not `acquire()` blocking in accept thread).
- **IO-005 vs CRY-002 / FAIL-002**: Aligned — non-loopback Control requires cookie or hashed password; IO owns bind gate, crypto/failure own auth.
- **IO-005 vs VPN / multi-iface product needs**: Allow non-loopback only with explicit opt-in; OnionVPN/HEV path should keep loopback Socks (`vpnDefaultConfig`). Do not weaken IO-005 for “convenience binds”.
- **IO-006 vs `CookieAuthFileGroupReadable`**: Intentional group-read clashes with default `0600`. Resolve: default owner-only; group bit only when the torrc flag is set.
- **IO-007 vs RET-001 / CF-001 teardown**: Fail-closed engine teardown that `cancel()`s listener jobs **amplifies** FD leaks unless IO-007/008 land first (or in the same change). Order: close-in-`finally` → then aggressive cancel/teardown.
- **IO-003 vs MEM-001**: DNS flood fix should drop before resolve/cookie insert; cookie LRU alone is insufficient under UDP flood.

### From cpu

Cross-checks vs other `docs/safety/domains/*.md`:

| Clash | Domains | Resolution |
| --- | --- | --- |
| Accept caps vs decrypt storm | IO-001..003, CPU-001 | Caps are necessary but **not sufficient** — keep fail-closed refuse at accept; add cell/crypto budget separately. Do not raise `DEFAULT_TCP=256` to “fix” load tests. |
| Constant-time compare vs CPU | CRY-001, CPU | Prefer constant-time for secrets; cost is negligible vs CPU-002 python fork. |
| Engine teardown vs Main ANR | CPU-004, RET-001, CF-001, MEM-006/007, FAIL-001 | Fail-closed teardown **must** still run; move heavy close to IO/background, then clear `PlatformNatives.socketProtector` and recreate scope. |
| KIST accuracy vs process spawn | CPU-002/003, link scheduler | Prefer KIST_LITE / cached TCP_INFO over python; never block `writeMutex` on subprocess. |
| UDP flood drop vs framing CPU | IO-003, CPU-005, BUF | Drop datagrams when saturated **before** `ArrayList` accumulate; fix O(n²) buffer independently. |
| Consdiff reject vs CPU | RET keypin/consdiff, CPU-006/007 | Reject/quarantine bad diffs early; still precompile regex and avoid `removeAt` storms on accepted patches. |
| Padding DROP bursts vs decrypt storm | CPU-001, circpad | Cap `maxPaddingCells` / flush rate; do not disable padding for CPU without product review. |

### From type

See board **Conflicts → From type**. Highlights:

- TYP-001 ListenSpec validation must land with IO-005 loopback / FAIL-004 control auth (do not “fix” parse by binding `0.0.0.0`).
- TYP-003 digest unification vs RET-003 verify-enforcement — same AUTH0003 path.
- TYP-004 drop ASCII SUBPROTO vs elevation tests that assert Trunnel strings — update tests to binary.
- TYP-005 named socks roles vs NUL-004 `-1` port sentinels — getters stay `-1` only when role absent.
- TYP-006 fail-closed CERTS casts vs RET-006 silent `runCatching` — prefer hard fail over soft null.
- TYP-002 typed mux policy vs CF mux attach / CPU fairness — no `Any?` “to ship faster”.
- TYP-008 / NUL-002 / MEM-002: return `HopKeys` under mutex before any cache eviction.

### From return

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

### From bounds

| Clash | Domains | Note |
| --- | --- | --- |
| Variable-cell max vs CERTS/VERSIONS real size | BND-003, BUF, MEM | Cap must still allow legitimate CERTS/AUTH blobs; prefer fail-closed close over silent truncate of auth material |
| Length `require` vs exception catch | BND-001/002/004, FAIL | Prefer explicit length checks returning destroy/reject **before** `copyOfRange`; do not rely on `try`/`runCatching` as bounds mitigation |
| TunFakeDns re-walk vs parse-once | BND-006/007, MEM-001 | Validating once in `parseQuery` is fine if builders take parsed offsets only — avoid dual parsers drifting |
| Relay V0 maxLen vs DATA chunking | BND-005, relay DATA | `sendRelayData` already chunks 498 (`RelayService.kt:1133`); encode-side maxLen is belt-and-suspenders, not a throughput conflict |
| LinkSpecifiers checked vs parseExtend2 unchecked | BND-001 | Consolidate on one checked link-spec walker (HS already safer) — no conflict, dedupe |
| DNS 512 buffer vs long names | BND-006, BUF-001/002 board | Truncate/FORMERR rather than grow buffer; aligns with DNSPort 512 |

### From crypto
- **CRY-001 vs FAIL-004 / IO-005**: Aligned — crypto owns auth fail-open; IO owns bind gate. Non-loopback Control requires cookie or hashed password; do not “fix” NULL for remote convenience.
- **CRY-001 vs lab/torrc NULL**: Loopback-only NULL for tests OK; product/VPN defaults keep `CookieAuthentication 1` (already default).
- **CRY-002 vs CPU micro-cost**: Always prefer constant-time for AUTH/MAC/KH; cost is negligible vs crypto.
- **CRY-003/005 vs GC / live hop keys**: Wipe ephemerals immediately after derive; live `HopCrypto`/`CgoHop` keys stay until circuit close — then wipe (order with MEM circuit teardown).
- **CRY-004 vs dir-circuit compatibility**: Disabling CreateFast on relay may break old clients; prefer config flag default-off for pure clients, default-on only when advertising legacy support.
- **CRY-006 vs IO-006 file perms**: Length/wipe (crypto) and `0600`/CookieAuthFile (io) are complementary; land together.
- **CRY-007 vs stale AUDIT_BOARD CRY-001**: Board still listed control `contentEquals` — superseded; control fixed, wire handshakes remain CRY-002.

### From buffer

Cross-checks against other domains:

| Clash | Domains | Note |
| --- | --- | --- |
| Dump/tag caps vs diagnostics | BUF-002, MEM | Prefer hard tag+body caps; diagnostics lose oldest dumps under flood — do not remove `take(64_000)` |
| Dir `StringBuilder` vs DirPort 64KiB header | BUF-003, BND | Align BEGIN_DIR cap with DirPort `:304` 65536; fail-closed END stream |
| DATA coalesce size vs latency / SENDME | BUF-004, circuit flow | Cap inbuf bytes; coalesce only within cap; do not raise `Channel.UNLIMITED` to “fix” throughput |
| Compression bomb reject vs large consensus | BUF-005, dir | Absolute out ceiling (tens of MiB) + ratio; legitimate consensuses must stay under ceiling |
| Larger TUN MTU vs MEM | BUF-006, MEM | Size buf from real MTU; drop oversize rather than allocate jumbo by default |
| Cell `copyOf` vs zero-copy | BUF-007, CPU | Keep copy at trust boundary; bound queue depth instead of sharing mutable buffers |
| DNS shared-buf copy vs UDP flood | BUF-001, IO-003 | Keep copy; IO in-flight semaphore is the DoS control |

### From null

Cross-checks against other `docs/safety/domains/*.md`:

| Clash | Domains | Note |
| --- | --- | --- |
| `hopKeys!!` vs cache eviction | NUL-002, TYP-002, MEM-002, CF-003 | **Return** `HopKeys` from ensure under same `mutex` as eviction; never `!!` after map get. Evict only unused FPs. |
| Consensus snapshot vs map mutex | NUL-003, CF-003, MEM-002 | All consensus reads + hopKeys ensure share one lock/atomic ref; HS must not race bootstrap null. |
| `protect(-1)` vs fail-closed dial | NUL-004, RET-002, MEM-006 | Do not invoke protector with `-1`; treat missing FD as protect failure; clear static protector on stop. |
| Engine `-1` ports vs UI/VPN | NUL-004, prior demo-ui | UI must gate on `isRunning && port > 0`; prefer nullable APIs over `-1`. |
| `dirPort == 0` HTTP vs BEGIN_DIR | NUL-005, IO dir | Prefer OR BEGIN_DIR; do not “fix” by probing `:0`. |
| OrConnection `!!` vs cancel close | NUL-006, IO-007, RET-001 | Close/null streams before cancelling reader; land with teardown order. |
| Fabricated DirPort 9030 vs bind policy | NUL-007, IO-005, CRY-002 | Invented ports conflict with “explicit bind + auth”; fail config instead. |
| Partial-start null refs | NUL-008, RET-001, FAIL-001, CF-001 | Single teardown helper wins; do not leave half-null listener set. |
| Optional ed hop keys vs crypto strength | NUL-001, CRY | Fail closed > silent classic-ntor downgrade when peer advertised ntor-v3. |

### From integer

- **INT-001 vs performance / “lite” codecs:** Checked `requireU16`/`requireU32` on every cell encode adds branches; still mandatory on wire lengths — fail closed over silent truncate (aligns BUF/BND).
- **INT-002 vs INT CircMux attach:** Uniqueness retry must be atomic with `circuitChannels` / `CircuitMux.attach` or CF-TOCTOU replaces one race with another.
- **INT-003/006 vs stream DoS:** Hard u16 space → need stream cap / circuit close (MEM/CPU accept caps); do not widen streamId beyond tor-spec.
- **INT-004 vs ListenSpec port 0 (auto):** `0` is valid for ephemeral bind; gate `1..65535` only for BEGIN/HS/exit-policy, allow `0` for listen-auto.
- **INT-005 vs dir-spec Bandwidth=:** Capping advertise `Int` must not invert relative weights (use saturating max consistently in vote/bridge status).
- **INT-007 vs Automap-generated IPs:** Generator already emits 0..255; keep check anyway for non-Automap cache/forward paths.
- **INT-008 vs crypto/timing:** Seq wrap tests must not weaken Conflux SWITCH ordering checks when those land (controlflow).

### From failure

- **Proxy gate vs DNSCrypt/OnionVPN ready contract**: Docs require SOCKS+DNSPort up before DNSCrypt; fail-closed “no bind until DONE” delays that plane — prefer bind control-only early, delay SOCKS CONNECT until DONE (or return SOCKS failure code without clearnet fallback).
- **VPN `safeSocksAllowIpLiterals` vs SafeSocks fail-closed**: Fake-IP TUN needs IP destinations — do not flip global allow; scope exception to Automap/fake-IP cookies only (tensions with FAIL-007 fix).
- **NULL control auth vs control-spec**: Spec allows NULL; safety requires bind policy (IO-005) rather than removing NULL entirely.
- **Teardown `daemon.stop()` cancels scope vs restart (CF-001)**: Fail-closed cleanup must recreate engine scope on next start — same conflict as RET/CF.
- **Fail-closed loopback bind vs product ports**: OnionVPN allocated loopback ports remain loopback; no conflict with FAIL-004 remediations.

