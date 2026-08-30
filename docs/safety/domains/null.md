# Domain: null

**Scope:** main Kotlin (`core` / `proxy` / `control` / `android` / `cli`).  
**Focus:** `!!` assertions, unchecked Map gets, nullable engine/daemon after stop, race NPE on concurrent stop/start, Optional-like gaps, platform null from JNI/Android APIs, silent null meaning failure.  
**Pass:** 2026-08-03 re-verify · mailbox `/tmp/ktor-safety-pass` (peers: return/memory/type/cpu/io/bounds).  
**Cap:** ~8 Critical/High.

## Status rollup

| ID | Risk | Status | One-liner |
|----|------|--------|-----------|
| NUL-001 | High | **OPEN** | Optional hop `ed25519Identity` → silent ntor-v3 downgrade / omit LSTYPE=3 |
| NUL-002 | High | **OPEN** | `hopKeys[fp]!!` after ensure — NPE under FIFO eviction / unsynchronized Map |
| NUL-003 | High | **OPEN** | HS wired to `consensusOrNull()`; DoS apply no-ops on null; unlocked snapshot API |
| NUL-004 | High | **OPEN** | Port `-1` sentinels + `protect(-1)` treated as usable FDs/ports |
| NUL-005 | High | **OPEN** | HSDir HTTP uses consensus `dirPort` (often `0`) → `host:0` URLs |
| NUL-006 | High | **OPEN** | `OrConnection` `input!!`/`output!!`/`socket!!` on OR send/read/handshake |
| NUL-007 | High | **OPEN** | Nullable `orPort`/`dirPort`/`address` → fabricated listen/publish defaults |
| NUL-008 | High | **FIXED** | Partial-start teardown nulls listeners + stops daemon (`teardownPartialStart`) |

**Counts:** FIXED **1** · OPEN **7** · NEW **0**  
**Top 3 open:** NUL-002 · NUL-006 · NUL-004

No standalone Critical-only null finding; strongest cluster is High. Partial-start Critical overlap closed via RET-001 (NUL-008). Residual stop↔start race ownership: **CF-002**.

---

### [NUL-001] Optional hop ed25519 / ntor keys silently degrade CREATE/EXTEND — **OPEN**
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `circuit/Circuit.kt:25-28` — `HopKeys.ed25519Identity` nullable
  - `:197-203` / `:291-303` — `keys.ed25519Identity ?: router.ed25519Identity`; if both null and peer `supportsNtorV3()`, fall through to classic ntor **without** ed linkspec
  - `dir/Consensus.kt` / `DescriptorParser` — `ntorOnionKey` / `ed25519Identity` optional on status/desc
  - `hs/OnionClient.kt:145+`, `OnionService.kt` rend hop may lack ed
- **Risk**: High (silent crypto/protocol downgrade; incomplete EXTEND linkspecs)
- **Fix**: Fail closed when Relay≥4 / ntor-v3 path needs ed but identity missing; never silently omit LSTYPE=3; missing ntor onion key = hard error before dial
- **Related**: CRY handshake, MEM-002 (key cache), TYP

### [NUL-002] `hopKeys[fp]!!` after ensure — **OPEN** (amplified)
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `TorClient.kt:108-110` — OnionClient callback: `ensureHopKeys(fp)` then `hopKeys[fp]!!` (no mutex)
  - `:374-385` — `ensureHopKeys` puts then FIFO-evicts when `size > MAX_HOP_KEYS` (512); may accept `docs.values.firstOrNull()` on FP mismatch
  - `:428-430` — `hopKeysFor` → ensure then `!!`
  - `hopKeys` is `linkedMapOf` (not concurrent); onion path releases client mutex before HS work (`:217-219`)
  - **MEM-002 FIXED** made eviction real → `!!` NPE **more** likely under descriptor churn
- **Risk**: High (NPE; wrong-descriptor put still “succeeds” with stale semantics)
- **Fix**: `ensureHopKeys(): HopKeys` return value under same lock as eviction; drop `!!`; refuse descriptor whose fingerprint ≠ requested `fp`
- **Related**: TYP-008, MEM-002 FIXED residual, MEM-010, CF map races

### [NUL-003] Nullable consensus on HS / unlocked snapshot — **OPEN**
- **Track**: null
- **Status**: OPEN (partial mitigation on SOCKS path only)
- **Evidence**:
  - `TorClient.kt:96` — `private var consensus: Consensus? = null`
  - `:218` — onion `connect` reads under `mutex` (good)
  - `:221-228` / `:234` — clearnet `connect`/`resolve` hold mutex around `circuitForIsolation` (consensus read gated)
  - `:422` — `consensusOrNull()` unlocked
  - `TorDaemon.kt:258` — `onionServices.consensus = { client.consensusOrNull() }`
  - `hs/OnionService.kt:177`, `:250`, `:410` — `consensus?.invoke() ?: error(...)` (fail if unset callback; still races bootstrap null)
  - `:259` — `HsDosDefense.applyConsensus(consensus?.invoke())` — **null silently no-ops** DoS param refresh
- **Risk**: High (HS start/publish vs bootstrap; DoS defense stays default when consensus absent)
- **Fix**: Atomic/`mutex` snapshot for all consensus reads; HS `startAll` await non-null consensus before intro/publish; pass `Consensus` (non-null) into DoS apply after gate
- **Related**: CF bootstrap ordering, FAIL-002, RET Conflicts (stale “NUL-003” = teardown — that is **NUL-008**)

### [NUL-004] Port / FD `-1` sentinel misuse — **OPEN**
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:56-61` — `socksPort`/`dnsPortBound`/`controlPort`/… → `-1` when unbound/stopped
  - `os/PlatformNatives.kt:226-234` — `protectSocket` invokes `protector(-1)` when FD unavailable, returns `false`
  - `config/TorConfig.kt` `ListenSpec.parse` — `toInt()` accepts negative port strings (TYP-001 / INT-004)
  - `dir/DescriptorPublisher.kt:39` — HTTP `code = -1` on I/O error (sentinel overload)
- **Risk**: High (UI/VPN dial or `VpnService.protect(-1)`; callers treat `-1` as live port)
- **Fix**: Prefer `Int?` / `boundPortOrNull()`; never pass `-1` to protect (align RET-002 fail-closed); reject `port < 0` in parse; keep HTTP error codes separate from listen ports
- **Related**: RET-002 OPEN, MEM-006 FIXED, TYP-005 roleSocks `-1`

### [NUL-005] Consensus `dirPort == 0` used as HTTP directory URL — **OPEN**
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `hs/HsDirClient.kt:118-120` — `http://${dir.ip}:${dir.dirPort}/tor/hs/3/$id` for every selected HSDir
  - `dir/Consensus.kt` — `dirPort: Int` commonly `0` when relay has no DirPort
  - Clearnet: `DirectoryClient.kt:41+`, `DescriptorPublisher.kt:21`
- **Risk**: High (HS fetch `*:0`, timeout burn, weak HS availability)
- **Fix**: Skip `dirPort <= 0` for HTTP dir; use BEGIN_DIR over ORPort when DirPort absent; assert `port in 1..65535` before URL build
- **Related**: IO dir path, HS client

### [NUL-006] `OrConnection` force-unwraps nullable socket streams — **OPEN**
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `link/OrConnection.kt:60-62` — `socket`/`input`/`output` nullable
  - `:228` — handshake `CellCodec.read(input!!, …)`
  - `:341` — `socket!!.localAddress` NETINFO
  - `:363` — read loop `input!!`
  - `:424-425`, `:479-480` — `output!!.write` / `flush`
- **Risk**: High (NPE on OR hot path after close, failed connect, or racing `stop`/cancel)
- **Fix**: Local non-null vals after successful `connect`; `send`/`readLoop` check open and throw typed closed; null fields under write mutex on close
- **Related**: IO-007, CF-002 teardown, RET-001, CPU-003 write path

### [NUL-007] Nullable listen/config fields on daemon & relay publish — **OPEN**
- **Track**: null
- **Status**: OPEN
- **Evidence**:
  - `config/TorConfig.kt:20-23` — `orPort`/`dirPort`/`metricsPort`/`address` nullable
  - `TorDaemon.kt:270-271` — auth cert mint: `dirPort?.host ?: "127.0.0.1"`, `dirPort?.port ?: 9030`
  - `relay/RelayService.kt:191-197` — `orPort ?: return`; `dirPort?.port ?: 0` into descriptor; `address ?: or.host`
  - `pt/PtServerManager.kt` — `config.orPort ?: config.extOrPort`
- **Risk**: High (mis-published OR/Dir endpoints; dirauth cert lies about listen)
- **Fix**: Require explicit ORPort/DirPort before auth/relay publish; no silent `9030`/`127.0.0.1`
- **Related**: IO-005, FAIL config validation, CRY-002 bind/auth

### [NUL-008] Partial-start leaves inconsistent non-null listener refs — **FIXED**
- **Track**: null
- **Status**: FIXED (Phase B / RET-001 / SAFETY_AUDIT)
- **Evidence (current)**:
  - `KotlinTorEngine.kt:147-155` — catch → `teardownPartialStart()` then clear `running`/`bootstrapped`
  - `:159-170` — `stop()` teardown + clear `PlatformNatives.socketProtector` + `scope.cancel`
  - `:192-205` — stops `socks` / `roleSocks` / `dnsPort` / `httpConnect` / `control`, nulls refs, `daemon.stop()`
  - `:184-188` — `ensureScope()` recreates scope + `TorDaemon` after cancel
- **Residual (not re-opened)**: Concurrent stop↔start still **CF-002** (late assigns vs teardown nulls). `bootstrapped` early set = FAIL-002, not missing null teardown.
- **Related**: RET-001 FIXED, FAIL-001 (peer docs may lag), CF-002 OPEN, MEM-006/007

---

## Conflicts

### Static

| Clash | Domains | Note |
| --- | --- | --- |
| `hopKeys!!` vs cache eviction | NUL-002, TYP-008, MEM-002 FIXED | Return `HopKeys` under same lock as eviction; MEM cap made NPE real |
| Consensus snapshot vs map mutex | NUL-003, CF, MEM-002 | HS/`consensusOrNull` must share lock/atomic; DoS must not silent-null |
| `protect(-1)` vs fail-closed dial | NUL-004, RET-002 OPEN, MEM-006 FIXED | Do not invoke protector with `-1`; treat missing FD as protect failure |
| Engine `-1` ports vs UI/VPN | NUL-004, TYP-005 | Gate on `isRunning && port > 0`; prefer nullable APIs |
| `dirPort == 0` HTTP vs BEGIN_DIR | NUL-005, IO | Prefer OR BEGIN_DIR; do not probe `:0` |
| OrConnection `!!` vs cancel close | NUL-006, IO-007, RET-001, CF-002 | Close/null streams before cancelling reader |
| Fabricated DirPort 9030 vs bind | NUL-007, IO-005 | Fail config instead of inventing ports |
| Partial-start null refs | NUL-008 FIXED, RET-001 FIXED | Peer FAIL/RET may still say “NUL-003” for teardown — **ID is NUL-008** |
| Optional ed vs crypto strength | NUL-001, CRY | Fail closed > silent classic-ntor downgrade |

### Live (mailbox `/tmp/ktor-safety-pass`)

| Peer claim | Resolution |
| --- | --- |
| RET-001 FIXED; Related still cites “NUL-003” for teardown | **Map teardown → NUL-008 FIXED**; keep NUL-003 = consensus/HS null |
| MEM-002 FIXED + TYP-008 / NUL-002 | Aligned: eviction amplifies `!!` — NUL-002 stays OPEN, top priority |
| RET-002 OPEN + NUL-004 `protect(-1)` | Land fail-closed protect + stop passing `-1` together |
| CF-002 engine stop↔start race | NUL-008 FIXED does **not** close CF-002; residual NPE on late `socks=` is CF |
| IO-007 cancel vs NUL-006 | Close sockets in `finally` before cancel; then drop OR `!!` |
| No mailbox conflict requiring NUL renumber | IDs NUL-001..008 stable; NEW=0 |
