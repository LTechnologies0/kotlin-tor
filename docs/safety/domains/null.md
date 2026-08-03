# Domain: null

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

## Conflicts

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
