# Domain: cpu

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

## Conflicts

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
