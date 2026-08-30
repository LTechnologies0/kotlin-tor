# Domain: cpu

**Scope:** main Kotlin (`:core`, `:proxy`, `:control`, `:android`). Focus: busy-wait, ReDoS / regex thrash, string|byte-in-loop, Android main-thread I/O via `KotlinTorEngine`, cell decrypt storms, KIST python fork, soft-spin under locks.  
**Cap:** ~8 findings. Accept-path concurrency caps (`ProxyAcceptLimits`) landed under IO; this domain covers residual **CPU** cost.  
**Pass status (2026-08-03+):** FIXED=1 · OPEN=7 · NEW=0  
**Top open (Critical/High):** CPU-003, CPU-004, CPU-001

## Critical / High summary

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| CPU-001 | **OPEN** | **High** | Per-cell multi-hop peel/encrypt with no crypto budget → decrypt storm under load |
| CPU-002 | **FIXED** | **Critical** | Full KIST python3 opt-in only; default select KIST_LITE/VANILLA |
| CPU-003 | **OPEN** | **High** | OR write-budget soft-spin (≤64×`delay(1)`) under `writeMutex` |
| CPU-004 | **OPEN** | **High** | `KotlinTorEngine.stop` / VpnService teardown does sync socket+daemon work on caller (often Main) |
| CPU-005 | **OPEN** | **High** | SOCKS UDP frame accumulate uses `ArrayList<Byte>` + `removeAt(0)` → O(n²) |
| CPU-006 | **OPEN** | **Medium** | Hot parsers recompile `Regex("\\s+")` / `matches(Regex(...))` per line/token |
| CPU-007 | **OPEN** | **Medium** | Untrusted text × regex (`findAll` / consdiff / control) → ReDoS-class CPU |
| CPU-008 | **OPEN** | **Medium** | Soft busy-waits: `StreamShaper` pause spin, `AddressSet` CAS, PT CMETHOD poll-sleep |

---

### [CPU-001] Cell decrypt / encrypt storm (no crypto budget)
- **Status**: OPEN
- **Track**: cpu
- **Evidence**:
  - `core/.../circuit/Circuit.kt:138-144` — every inbound `RELAY`/`RELAY_EARLY` calls `layers.decryptRelay`; undecryptable path still `System.err.println`
  - `core/.../circuit/CircuitCrypto.kt:177-191` — peels **all hops** (AES-CTR+digest or CGO UIV) until recognized
  - `core/.../relay/RelayService.kt:501-509` — relay path `peelFromClient` per cell
  - Outbound: `encryptRelay` walks hops (`CircuitCrypto.kt:163-174`); padding `flushPendingDrops` sends DROP cells in a tight loop (`CircuitPaddingMachines.kt:179-185`)
- **Risk**: High
- **Fix**: Keep IO accept caps; add per-circuit / per-OR **cell or CPU token budget** (drop or queue when exhausted). Prefer in-place CGO buffers; rate-limit DROP bursts; avoid `System.err` on hot undecryptable path.
- **Related**: IO-001..003 (`ProxyAcceptLimits` reduces spawn rate but not cells/sec once connected), MEM-003, CRY constant-time (do not weaken crypto for speed)

### [CPU-002] KIST TCP_INFO via per-call `python3` process — **FIXED** (mitigated)
- **Status**: FIXED / mitigated
- **Track**: cpu
- **Evidence**:
  - `ChannelScheduler.select` skips full KIST unless `LinuxTcpInfo.isFullKistEnabled()` (`KOTLIN_TOR_KIST_PYTHON=1`)
  - `LinuxTcpInfo` documents python3 as debug/opt-in; `queryFd` returns null unless opted in
  - Default preference falls through to KIST_LITE / VANILLA (no hot-path fork)
- **Risk**: was Critical
- **Residual**: Opt-in full KIST still forks python — native TCP_INFO remains future work
- **Related**: CPU-003, ChannelScheduler

### [CPU-003] Write-budget soft-spin under `writeMutex`
- **Status**: OPEN
- **Track**: cpu
- **Evidence**: `core/.../link/OrConnection.kt:416-422` — `while (!writeBudget.tryAllowFull(...)) { refill(...); if (++spins > 64) break; delay(1) }` inside `writeMutex.withLock`
- **Risk**: High
- **Fix**: Release mutex before wait; use suspend condition / channel credit (same pattern as `CircuitFlowControl.packageCredit`); after budget break, re-queue cell instead of spinning. Cap refill cost (CPU-002).
- **Related**: CPU-002, ChannelSchedulerPending drain fairness

### [CPU-004] Android engine stop / protect / TUN on caller thread
- **Status**: OPEN (partial adjacent: protector clear + `ensureScope` recreate)
- **Track**: cpu
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:102-156` — `scope` = `Dispatchers.Default`; `onReady` / `onError` / Orbot broadcast run there (not Main) — OK for UI if host hops
  - `:159-170` `stop()` synchronously calls `teardownPartialStart()` (SOCKS/DNS/HTTP/Control + `daemon.stop()`), TUN teardown, protector clear, `scope.cancel()` — **no** `Dispatchers.IO`
  - `:192-204` `teardownPartialStart` closes all listeners + `daemon.stop()` on caller thread
  - `android/.../KotlinTorVpnService.kt:217-228` `stopVpn()` → `engine?.stop()`; `:236-239` `onDestroy` (Main binder thread) → `stopVpn()`
  - `:69-94` `VpnTunnel.establishTun` / `Builder.establish()` from engine callbacks (Default) — protect is binder IPC; establish is heavy I/O
- **Risk**: High (ANR / jank when Service/Activity calls `stop`; Medium if host `onReady` touches Views without Main hop)
- **Fix**: Make `stop()`/`teardown` async on `Dispatchers.IO` (or `scope.launch` + join with timeout); document that `onReady`/`onError` are **not** Main; require UI hosts to `withContext(Main)`. Keep protect off Main but bound/fast.
- **Related**: CF-002 (stop↔start race), RET-001, MEM-006/007 (protector clear + scope recreate now present; ANR remains), FAIL teardown

### [CPU-005] Byte-in-loop O(n²) on SOCKS UDP framing
- **Status**: OPEN
- **Track**: cpu
- **Evidence**:
  - `core/.../net/FramingProtocols.kt:341-352` (and `:375-385`) — `ArrayList<Byte>()`; per read `acc.add`; parse then `repeat(used) { acc.removeAt(0) }`
  - Same class: `ProxyFrontends.kt:27` `push.removeAt(0)`; `RelayService.kt:690+` `ArrayList<Byte>` for RESOLVED; `CircuitCrypto.buildExtend2Data` (`:215+`) boxes handshake bytes
  - Related O(n²): `Circuit.kt:737-758` `readHttpResponse` — `ArrayList<Byte>` + full `decodeToString()` + Content-Length `Regex` per chunk (also BUF)
- **Risk**: High on UDP ASSOCIATE / large datagrams; Medium on EXTEND2/RESOLVE / BEGIN_DIR HTTP
- **Fix**: `ByteArray` + offset/length or circular buffer; `System.arraycopy` discard; never `removeAt(0)` in a loop.
- **Related**: BUF domain (buffer shape), TYP-007, IO UDP flood

### [CPU-006] Regex recompiled in directory / config / policy hot paths
- **Status**: OPEN
- **Track**: cpu
- **Evidence**:
  - `TorConfig.kt` — many `line.split(Regex("\\s+"))` inside parse switch (`:619+`)
  - `BandwidthVote.kt`, `DirList.kt`, `ProcessDescsAndAuthMode.kt`, `ControlServer.kt` — same per-token pattern
  - `KeypinAndConsDiff.kt:173` — `cmd.matches(Regex("""\d+(,\d+)?d"""))` **allocates Regex each command**
  - `NetworkPolicy.kt:180`, `RouterSetAndDlStatus.kt:44` — `matches(Regex(...))` per host/token
  - `LinuxTcpInfo.kt:82` — `split(Regex("\\s+"))` on every successful TCP_INFO probe
- **Risk**: Medium (startup / consensus / control); compounds under malicious large torrc or vote bodies
- **Fix**: `private val WS = Regex("\\s+")` (or `companion`) reuse; prefer `split(' ')` / index scanners for whitespace; precompile fingerprint / consdiff command patterns.
- **Related**: CPU-007, BUF dump/parse paths

### [CPU-007] ReDoS-class regex CPU on untrusted protocol text
- **Status**: OPEN
- **Track**: cpu
- **Evidence**:
  - `BinaryAppProtocols.kt:163-174` — `ATTR = Regex("""(\w+)=["']([^"']*)["']""")` then `findAll(t)` on full XMPP open (attacker-controlled size)
  - `ControlServer.kt:616-617` — `Regex("""(?m)^hs_blinded_id=(\S+)""")` constructed in HSPOST handler path
  - `KeypinAndConsDiff.kt:168-178` — consdiff apply: mutable line list + `removeAt` ranges (CPU + allocation); regex per delete cmd (CPU-006)
  - `Circuit.kt:752` — `(?i)Content-Length` regex compiled per HTTP chunk in `readHttpResponse`
- **Risk**: Medium (no nested `(a+)+` found in main; still unbounded match work on huge inputs)
- **Fix**: Cap input length before regex; use linear scanners for attrs / consdiff opcodes; precompile once; reject oversized control/HS/XMPP frames early (align IO/BUF caps).
- **Related**: CPU-006, IO control/DNS caps

### [CPU-008] Soft busy-waits and CAS spins
- **Status**: OPEN
- **Track**: cpu
- **Evidence**:
  - `BytePipe.kt` `StreamShaper.awaitUnpaused` `:59-62` — `while (paused) delay(5)` (poll)
  - `AddressSet.kt:32-35` — unbounded `compareAndSet` spin on bloom word
  - `PtManager.kt:84-87` / `PtServerManager.kt` — `repeat(50) { … Thread.sleep(100) }` CMETHOD wait (blocking thread, ~5s worst)
  - `TorDaemonDirAuthCluster.kt:97-110` — quorum poll `Thread.sleep(50)` (dir-auth cluster path)
- **Risk**: Medium (AddressSet CAS normally short; pause/PT/auth polls waste CPU or block threads under stuck peers)
- **Fix**: Pause → `Mutex`/`CompletableDeferred`; PT wait → `Channel`/`withTimeout` on reader events; AddressSet keep CAS but avoid nesting under hot locks; dir-auth use suspending delay on IO dispatcher.
- **Related**: CPU-003 (prefer credit channels over spin), multithreading / CF

## Conflicts

Cross-checks vs other `docs/safety/domains/*.md`:

| Clash | Domains | Resolution |
| --- | --- | --- |
| Accept caps vs decrypt storm | IO-001..003, CPU-001 | Caps (`ProxyAcceptLimits`) are necessary but **not sufficient** — keep fail-closed refuse at accept; add cell/crypto budget separately. Do not raise `DEFAULT_TCP=256` to “fix” load tests. |
| Constant-time compare vs CPU | CRY (auth/MAC), CPU | Prefer constant-time for secrets; cost is negligible vs CPU-002 python fork. |
| Engine teardown vs Main ANR | CPU-004, RET-001, CF-002, MEM-006/007, FAIL | Fail-closed teardown **must** still run; move heavy close to IO/background, then clear `PlatformNatives.socketProtector` (done) and recreate scope (done via `ensureScope`). ANR risk remains until async stop. |
| KIST accuracy vs process spawn | CPU-002/003, link scheduler | Prefer KIST_LITE / cached TCP_INFO over python; never block `writeMutex` on subprocess. |
| UDP flood drop vs framing CPU | IO-003, CPU-005, BUF | Drop datagrams when saturated **before** `ArrayList` accumulate; fix O(n²) buffer independently. |
| Consdiff reject vs CPU | RET keypin/consdiff, CPU-006/007 | Reject/quarantine bad diffs early; still precompile regex and avoid `removeAt` storms on accepted patches. |
| Padding DROP bursts vs decrypt storm | CPU-001, circpad | Cap `maxPaddingCells` / flush rate; do not disable padding for CPU without product review. |
| Cell `copyOf` vs zero-copy | BUF Conflicts, CPU-001 | Keep copy at trust boundary; bound queue/crypto budget instead of sharing mutable buffers. |
| `ArrayList<Byte>` builders | TYP-007, CPU-005 | Same remediation: typed `ByteArray` builders; TYP owns wire-type mistakes, CPU owns thrash. |

## Conflicts (live)

Read against sibling domain mailboxes this pass:

| Live note | Source | Action |
| --- | --- | --- |
| IO accept caps **landed** (`ProxyAcceptLimits` + Semaphores on Socks/HTTP/DNS/Control) | `io.md` IO-001..004 + code | Do **not** close CPU-001; caps only gate connection spawn. Still need cell/crypto budget. |
| IO Conflicts align fail-closed refuse (no blocking `acquire` on accept) | `io.md` Conflicts | Compatible with CPU-001 token budget (drop/queue cells, not block accept). |
| MEM cap-sizes vs throughput | `memory.md` Conflicts | Aligned: fail-closed reject/drop; do not raise caps for stress. |
| MEM-006 protector clear now in `stop()` | `memory.md` MEM-006 + `KotlinTorEngine.kt:165-167` | Partial for CPU-004 adjacent leak; **does not** fix Main-thread sync teardown. |
| MEM-007 / CF-002 scope recreate via `ensureScope` | `memory.md`, `controlflow.md` CF-002 | Restartability improved; CPU-004 ANR on `onDestroy`/`stopVpn` still OPEN. |
| CRY constant-time preferred over micro-opt | `crypto.md` Conflicts | Aligned with CPU Conflicts row. |
| BUF cell copy + DNS shared-buf | `buffer.md` Conflicts | Keep copy; CPU owns decrypt/framing thrash; IO owns flood semaphore. |
| BUF Circuit `readHttpResponse` O(n²) | `buffer.md` (ArrayList path) | Cross-listed under CPU-005 related; fix once for both domains. |
| TYP-007 `ArrayList<Byte>` wire builders | `type.md` | Same fix class as CPU-005; coordinate typed builders. |
| RET teardown order vs IO-007 FD close | `return.md` Conflicts | Async CPU-004 stop must still close sockets in `finally` before cancel (IO Conflicts order). |
| RET silent `runCatching` vs observability | `return.md` | Teardown `runCatching` OK; do not strip CPU-001 `System.err` without structured rate-limited log. |
| FAIL teardown / restart | `failure.md` Conflicts | Same as CF-002/MEM-007: recreate scope after fail-closed cleanup; prefer IO dispatcher for heavy close. |
| No mailbox conflict requiring finding ID renumber | all domains | IDs CPU-001..008 stable; NEW=0 this pass. |
