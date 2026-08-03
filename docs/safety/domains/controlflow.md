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
