# Domain: memory

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

## Conflicts

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
