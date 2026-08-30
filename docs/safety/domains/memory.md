# Domain: memory (re-audit)

**Scope:** main Kotlin (`core` / `proxy` / `control` / `android` / `cli`). Tests excluded unless they document unsafe API.  
**Focus:** leaks, unbounded maps/caches, missing `close`/`.use`, static retainers, `CoroutineScope` lifetime, circuit/connection table growth.  
**Pass:** verify prior remediations against **current** sources — mark FIXED / STILL OPEN / NEW.  
**Cap:** ~8 strongest Critical/High (Medium if space).

## Status rollup

| Status | Count | IDs |
| --- | --- | --- |
| **FIXED** | 3 | MEM-001, MEM-002, MEM-006 |
| **STILL OPEN** | 5 | MEM-003, MEM-004, MEM-005, MEM-007, MEM-008 |
| **NEW** | 2 | MEM-009, MEM-010 |

Supporting (not MEM IDs): `ProxyAcceptLimits` landed on SOCKS/HTTP/DNS/Control — mitigates accept→table growth but does **not** close MEM-003.

**Top 3 open (action priority):** MEM-005, MEM-003, MEM-009

---

## FIXED (verified)

### [MEM-001] FakeIpDnsCookies host→ip maps never expire — **FIXED**
- **Track**: memory
- **Evidence (current)**: `core/.../net/stack/FakeIpDnsCookies.kt:16-19`, `:119-152`, `:154-157` — `maxEntries` (default 8192); `pruneExpired` drops both `byIp` and `byHost`; `enforceCap` evicts oldest expiry and removes matching host keys
- **Risk**: was High
- **Residual**: TOCTOU check-then-insert still CF/CF-008 class; cap is per family, not process-wide with Automap

### [MEM-002] TorClient.hopKeys / isolatedCircuits unbounded — **FIXED**
- **Track**: memory
- **Evidence (current)**: `TorClient.kt:97`, `:103`, `:392-397`, `:451-453` — `MAX_HOP_KEYS=512`, `MAX_ISOLATED_CIRCUITS=128`; `ensureHopKeys` FIFO-evicts; `evictIsolatedIfNeeded` closes+removes oldest
- **Risk**: was High
- **Residual**: KeepAliveIsolateSOCKSAuth still sets dirty timeout ≈ infinity (`:246-253`) so circuits stay until **hard** 128 cap; eviction does **not** scrub `CircuitList`/`open` (see MEM-005); `PathSelector.families` not capped (MEM-010); `hopKeys[fp]!!` after ensure races eviction (NUL-002)

### [MEM-006] Static PlatformNatives.socketProtector retains VPN callback — **FIXED**
- **Track**: memory
- **Evidence (current)**: `KotlinTorEngine.kt:159-167` clears instance + `PlatformNatives.socketProtector`; `KotlinTorVpnService.kt:224` also clears on `stopVpn`
- **Risk**: was High
- **Residual**: process-global mutable hook remains; prefer engine-scoped holder long-term (RET-002 still fail-open on protect `false`)

---

## STILL OPEN / NEW (active findings)

### [MEM-005] Circuit.close leaves CircuitList / open / PathBias / OR map — **STILL OPEN** · High
- **Track**: memory
- **Evidence**:
  - `Circuit.kt:707-712` — `close()` only `unregisterCircuit` + clear streams; **no** `CircuitList.remove` / manager notify
  - `:872`, `:896` — success path `CircuitList.put` + `open[circId]=path`
  - `:904-905` — failure path removes from list; success+later `close()` does not
  - `:779-780`, `:838` — `connections` `getOrPut` never pruned when last circuit leaves
  - `PathBias.kt:76-85`, `:182-183` — `circState` filled on build; `forgetCircuit` only on build **failure** (`Circuit.kt:902`), not on `close()` / NEWNYM
- **Risk**: High (NEWNYM / isolation churn → unbounded `CircuitList` + `open` + `circState` + sticky `OrConnection`s)
- **Fix**: On close: `CircuitList.remove(id)`, `open.remove(id)`, `pathBias.forgetCircuit(id)`; drop idle OR from `connections` when `circuitChannels` empty; clear maps on NEWNYM/daemon stop
- **Related**: MEM-002 (evict calls `close()`), CF circuit lifecycle, CPU-001 (dead circuits still scheduled)

### [MEM-003] ConnectionTable has no ConnLimit — **STILL OPEN** · High
- **Track**: memory
- **Evidence**: `ConnectionSt.kt:155-211` — process-wide `ConcurrentHashMap`; `add`/`new*` never check `TorConfig.connLimit` (`TorConfig.kt:160-161`); `clear()` test-only. Accept caps (`ProxyAcceptLimits`, SOCKS/HTTP/DNS/Control) reduce spawn rate but Ftp/Transparent/Bilingual/FixedTor/UdpTorGateway still unbounded accept (`FtpTorProxy.kt:57-61`); missed `remove` on any error path still retains handles
- **Risk**: High
- **Fix**: Enforce soft max on `add` (reject/close when over ConnLimit); apply ProxyAcceptLimits to remaining AP acceptors; `finally` remove; optional idle sweep
- **Related**: IO-001..004 (partially remediated), CPU-001, FAIL accept flood, BUF-004

### [MEM-009] OnionClient.ed25519ByFp HSDir identity cache unbounded — **NEW** · High
- **Track**: memory
- **Evidence**: `OnionClient.kt:41`, `:390-410`, `:413-437` — `HashMap` grows on every HSDir descriptor fetch; `persistIdentityCache` rewrites full TSV with **no** max entries / TTL; survives process restart via `hsdir-ed25519.tsv`
- **Risk**: High (consensus HSDir churn → unbounded RAM + on-disk growth)
- **Fix**: Cap (e.g. 4096) with LRU; prune FPs not in current consensus; bound file rewrite size
- **Related**: MEM-002 (hopKeys capped, this sibling cache not), MEM-004 (HS caches), IO dir fetch storm

### [MEM-010] PathSelector.families grows after hopKeys eviction — **NEW** · Medium
- **Track**: memory
- **Evidence**: `TorClient.kt:386-389` — every `ensureHopKeys` may `paths.noteFamily`; `PathSelector.kt:46`, `:50-55` — `families` map inserts permanently; hopKeys FIFO eviction does **not** remove family edges
- **Risk**: Medium (descriptor churn fills family graph forever; weaker than MEM-005/009)
- **Fix**: Cap family map / drop edges when FP evicted from hopKeys; or rebuild families from live hopKeys only
- **Related**: MEM-002 residual, NUL-002

### [MEM-004] HsCache side maps unbounded; TTL clean never scheduled — **STILL OPEN** · Medium
- **Track**: memory
- **Evidence**: `HsCache.kt:41-44`, `:112-128`, `:155-168` — `trimDir`/`trimClient` only for `asDir`/`asClient`; `introByService` / `dirConnByKey` uncapped; `cleanAsDir`/`cleanAsClient`/`handleOom` never called from main (tests only); `OnionService.kt:127` owns a live `HsCache`
- **Risk**: Medium
- **Fix**: Bound intro/dirConn; call `cleanAs*` on timer / before store; wire `handleOom` to production OOM
- **Related**: CF-008 (HsCache `allocatedBytes` TOCTOU), BUF HS docs

### [MEM-008] Missing `.use` on cert / inflate / SOCKS-dir streams — **STILL OPEN** · Medium
- **Track**: memory
- **Evidence**:
  - `OrCertMaterial.kt:147-148` — `Files.newInputStream(...)` not closed
  - `DirectoryClient.kt:199` — `InflaterInputStream(...).bufferedReader(...).readText()` without `.use`
  - `DirectoryClient.kt:214` — `SocksDirectoryClient` `BufferedReader(InputStreamReader(conn.inputStream))` without `.use` / disconnect
- **Risk**: Medium (FD / native zlib retain on load/fetch paths)
- **Fix**: `.use { }` on all three; disconnect HTTP connections in `finally`
- **Related**: —

### [MEM-007] Dual VpnService scope + DirAuth orphan defaults — **STILL OPEN** · Medium
- **Track**: memory
- **Evidence**:
  - **Partial fix:** `KotlinTorEngine.kt:184-188` `ensureScope()` recreates scope+daemon after cancel; `:168` `scope.cancel()` on stop
  - **Still open:** `KotlinTorVpnService.kt:33`, `:238` — separate root scope cancelled only in `onDestroy` (not on `stopVpn`); dual trees vs engine
  - `TorDaemonDirAuthCluster.kt:80`, `:127` — default `CoroutineScope(SupervisorJob()+Default)` if caller omits parent
- **Risk**: Medium (orphaned jobs / delayed cancel; engine restart path OK)
- **Fix**: Share one supervised tree with VpnService; require explicit parent scope in library APIs
- **Related**: CF-002 (engine race), CPU-004 (sync stop), RET/FAIL teardown docs lag code

---

## Conflicts (static)

| Clash | Domains | Note |
| --- | --- | --- |
| Accept semaphore vs ConnectionTable cap | IO-001..004, MEM-003 | Prefer **both**: fail-closed refuse at accept **and** ConnLimit on `ConnectionTable.add`. ProxyAcceptLimits alone ≠ MEM-003 closed. |
| Fake-IP atomic insert vs eviction | CF-008, MEM-001 FIXED | Cap+prune landed; still compose eviction with atomic insert for both map directions. |
| isolatedCircuits LRU close vs list scrub | NUL-002, MEM-002 FIXED, MEM-005 | Cap eviction calls `close()` that does **not** scrub `CircuitList`/`open`/`circState` — MEM-005 remains the real leak under KeepAlive. |
| hopKeys eviction vs `!!` | NUL-002, TYP-008, MEM-002 | Returning `HopKeys` from `ensureHopKeys` under same lock as eviction; never `!!` after get. |
| Engine scope recreate vs Vpn dual root | CF-002, CPU-004, MEM-007 | Engine recreate FIXED; VpnService still owns second root — cancel on `stopVpn` or share parent. |
| Cap sizes vs throughput | CPU-001, IO | Fail-closed reject/drop; do not raise caps to green stress tests. |
| UnparseableDump tags | BUF-002 | Body `take(64_000)` exists; tag count still unbounded — align with MEM map-cap pattern. |
| HsCache model | MEM-004 | Dir/client trim real; intro/dirConn + unscheduled `cleanAs*` remain. |
| Teardown / protect | RET-001 FIXED (mailbox), RET-002 OPEN, MEM-006 FIXED | Teardown + protector clear on `stop` aligned; RET-002 fail-closed protect still required. |

## Conflicts (live)

_Re-read `/tmp/ktor-safety-pass/{return,type,bounds,cpu,io,memory}.md` after draft. Peers agree on several remediations; residual clashes below._

| Clash | Peer claim vs MEM | Resolution preference |
| --- | --- | --- |
| RET-001 **FIXED** (mailbox) | Confirms `teardownPartialStart` + protector clear on `stop`; partial-start catch intentionally leaves static protector for VPN re-attach | Align: MEM-006 FIXED; do not clear protector in catch-only path |
| RET-002 **OPEN** protect fail-open | Orthogonal to MEM-006 clear-on-stop | Keep MEM clear; RET must fail-closed when protector set |
| RET-008 silent RefreshCircuits | NEWNYM/`close()` without MEM-005 scrub → circuits “gone” in client maps but still in `CircuitList`/`open` | Surface refresh failures (RET) **and** scrub tables (MEM-005) |
| IO-001..004 FIXED + **IO-009 NEW** | Secondary AP acceptors (TransPort/UdpGw/Ftp/…) still uncapped; IO explicitly keeps MEM-003 OPEN | Prefer IO-009 caps **and** ConnLimit on `ConnectionTable.add` |
| IO / CPU “caps not sufficient” | Aligned with MEM Conflicts: do not raise `DEFAULT_TCP` to soak tests | Fail-closed reject/drop; cell budget is CPU-001, not MEM |
| CPU-004 sync `stop` on Main | Protector clear + `ensureScope` noted done; ANR remains | Order: close sockets → clear protector → cancel/recreate; move close to IO |
| TYP-008 / NUL-002 `hopKeys!!` | MEM-002 FIXED makes eviction real → NPE more likely | Return `HopKeys` from `ensureHopKeys` under same lock (TYP/NUL own API; MEM owns cap) |
| BND-003 variable-cell alloc | Uncapped `readNBytes(len)` → large transient alloc (MEM pressure) | Cap length (BND) before MEM worries about retained heap; fail-closed close |
| BND-006 vs MEM-001 | Fake-IP flood related; MEM-001 FIXED (cookie cap) | Keep DNS drop-before-insert (IO-003); builders must not reintroduce unbounded walks |
| BUF-004 `Channel.UNLIMITED` | Amplifies MEM-005 retained circuits holding stream channels | Scrub circuits (MEM-005) **and** bound channels (BUF) |
| CF-002 engine race | MEM-007 engine recreate helps restart; `running` race remains CF | MEM does not claim CF-002 fixed; VpnService dual scope still MEM-007 OPEN |
