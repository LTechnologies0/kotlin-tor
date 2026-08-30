# Control-flow domain audit (CF)

**Repo:** kotlin-tor · **Scope:** main sources (`core/`, `android/`, `control/`, `proxy/`)  
**Focus:** OR handshake FSM, HS intro FSM, circuit EXTEND races, dormant gate, CHM TOCTOU, `KotlinTorEngine` / `TorDaemon` stop↔start, accept-after-close, auth workflow bypass  
**Pass:** 2026-08-03 re-verify · mailbox `/tmp/ktor-safety-pass` (RET/TYP/BND/IO/MEM/CPU present; FAIL only in-repo)  
**Cap:** ~8 Critical/High in priority table · **Risk filter:** Critical / High

## Pass status

| Bucket | Count | IDs |
|--------|-------|-----|
| **FIXED** | 2 | CF-001, CF-002 |
| **OPEN** | 6 | CF-003, CF-004, CF-005, CF-006, CF-007, CF-008 |
| **NEW** | 1 | CF-009 (EXTEND2 async vs DESTROY / orphan CircState) |

**Priority table (Critical/High open):** CF-009 · CF-003 · CF-005 · CF-004 · CF-006 · CF-008  

**Top 3 open:** `CF-009` · `CF-003` · `CF-005`

---

## Critical / High summary

| ID | Status | Risk | One-line |
|----|--------|------|----------|
| [CF-001] | **FIXED** | Critical | OR handshake requires CERTS; identity pin hard-fail on null/mismatch |
| [CF-002] | **FIXED** | Critical | Engine lifecycle IDLE\|STARTING\|RUNNING\|STOPPING + CAS stop ownership |
| [CF-009] | **NEW** | High | Relay `EXTEND2` launched async; DESTROY / peel race can orphan or double-wire `CircState.next` |
| [CF-003] | **OPEN** | High | HS intro `HsIntroFsm` is bookkeeping only; INTRODUCE2 never gates on ESTABLISHED |
| [CF-005] | **OPEN** | High | `ReplayCache.addAndTest` horizon refresh non-atomic → dual INTRODUCE2 accept after TTL |
| [CF-004] | **OPEN** | High | `HsIntroPointTable` mutable FSM cells in `ConcurrentHashMap` (lost updates / stale CLOSED) |
| [CF-006] | **OPEN** | High | `TorDaemon.stop` / `start` TOCTOU on `started` AtomicBoolean (no CAS teardown) |
| [CF-008] | **OPEN** | High | Cross-map CHM TOCTOU: Keypin check-then-add, Fake-IP allocate, HsCache `allocatedBytes` |
| [CF-007] | **OPEN** | High | Soft dormant: check-then-act on `@Volatile dormant` admits streams after DORMANT |

---

### [CF-001] OR handshake requires CERTS + identity pin — **FIXED**
- **Track**: controlflow
- **Status**: FIXED
- **Evidence**: `OrConnection.performHandshake` requires `sawVersions && sawCerts && sawNetinfo`; `expectedIdentityHex != null` fails if peer FP null or mismatches; `CertsCell` hard-fails type-2/4 extract; TorSsl notes CERTS binding mandatory
- **Related**: CRY-009 FIXED, RET-006 residual soft paths, RET-003 still OPEN on relay AUTH verify

### [CF-002] `KotlinTorEngine` stop↔start lifecycle CAS — **FIXED**
- **Track**: controlflow
- **Status**: FIXED
- **Evidence**: `KotlinTorEngine` — `AtomicReference` lifecycle IDLE→STARTING→RUNNING; `stop()` claims STOPPING, cancels/joins start job, teardown, then IDLE; `start` only CAS from IDLE
- **Related**: RET-001, CPU-004 (sync stop still Main-risk), CF-006 TorDaemon residual

### [CF-009] Relay EXTEND2 async vs DESTROY / CircState race — **NEW**
- **Track**: controlflow
- **Status**: NEW (High)
- **Evidence**:
  - `RelayService.kt:511-526` — on EXTEND2 sets `st.extending=true` then `scope.launch { handleExtend2(...) }` (not awaited on the OR read loop)
  - `:498-499` — DESTROY `circuits.remove(cell.circId)?.next?.close()` while extend job may still run
  - `:1077-1079` — success path assigns `st.next` / `st.nextCircId` / `st.extending=false` on the **same** `CircState` object even if map entry already removed
  - `:1111-1118` — failure clears `extending` and may TRUNCATED-write on a circuit already destroyed
  - `:632-643` — forward path uses `st.next` without checking `extending` (cells during in-flight extend → “no next hop” drop)
- **Risk**: High
- **Exploit logic**: Client EXTEND2 then DESTROY (or second peel path) while next-hop CREATE2 in flight → orphan OR connection retained on detached `CircState`, or late `st.next=` after remove leaks FD / double-close when `finally` closes all `circuits.values` **and** DESTROY already closed next. Order-of-operations: extend completion after circuit death = workflow race, not an FSM.
- **Fix**: Serialize extend on per-circuit mutex; on DESTROY cancel extend job and null `next` under same lock; `handleExtend2` must re-check `circuits[circId] === st` before publishing `next`; fail-closed TRUNCATED only if circuit still live.
- **Related**: CF-001 (next-hop `connect` identity), BND-001/002 EXTEND parse, MEM-005 circuit table scrub.

### [CF-003] HS intro FSM not a control gate for INTRODUCE2 — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High)
- **Evidence**: FSM enum `HsCommonConfigDos.kt:155-161`; transitions `:176-209`; live use `OnionService.kt:195-199` (`beginEstablish`/`noteEstablished`), `:266` (`noteIntroduce` after DoS admit), `:242-307` (`handleIntroduce2` never reads `fsm`); establish failure `:208-209` logs only — no `noteClosed`
- **Risk**: High
- **Exploit logic**: `noteIntroduce` mutates counters only if entry exists; does **not** reject CLOSED/ESTABLISHING/NONE. `handleIntroduce2` decrypts/rendezvous regardless. FSM can sit ESTABLISHING forever after throw post-`beginEstablish`, yet late INTRODUCE2 on reused `IntroPointLive` still handled.
- **Fix**: Allowlist transitions; require `fsm ∈ {ESTABLISHED, INTRO_RECEIVED}` before decrypt; `noteClosed` on establish failure; refuse when CLOSED.
- **Related**: CF-004, CF-005, RET-007 ADD_ONION publish race.

### [CF-004] Mutable intro state in ConcurrentHashMap (FSM TOCTOU) — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High)
- **Evidence**: `HsCommonConfigDos.kt:173-209` — `byAuth: ConcurrentHashMap<String, HsIntroPointState>` with `var fsm` / `var introduceCount`; `beginEstablish` unconditional overwrite
- **Risk**: High
- **Exploit logic**: Map ops atomic per key; field updates racy. Concurrent `noteIntroduce` / `noteClosed` lose increments or leave `established=true` with `fsm=CLOSED`. `beginEstablish` replaces ESTABLISHED without CLOSE → listeners on old circuit, table points at new ESTABLISHING key.
- **Fix**: Immutable snapshots via `compute`/`merge`, or per-key lock; CAS `transition(from,to)`; never overwrite ESTABLISHED without CLOSE.
- **Related**: CF-003; `HsCache.IntroState` (`HsCache.kt:34-39`, `:112-119`).

### [CF-005] ReplayCache horizon refresh race (dual accept) — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High)
- **Evidence**: `ReplayCache.kt:24-33`; call site `OnionService.kt:305-307`
- **Risk**: High
- **Exploit logic**: After `putIfAbsent` hits aged entry, non-atomic `seen[key]=now` + return non-replay. Two threads observing same expired digest both refresh → dual INTRODUCE2 decrypt + rendezvous. Replay check also sits **after** DoS/metrics increments (order-of-operations).
- **Fix**: Single `compute` returning replay boolean; or `replace(key, prev, now)` and treat failed replace as replay. Move replay before metrics when possible.
- **Related**: CF-003.

### [CF-006] TorDaemon `started` stop without ownership CAS — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High)
- **Evidence**: `TorDaemon.kt:135-136` (`compareAndSet(false,true)` on start); `:329-340` (`if (!started.get()) return` then tear down, `started.set(false)` last)
- **Risk**: High
- **Exploit logic**: Start holds CAS; stop only reads then clears. Concurrent `stop` during `client.bootstrap()` cancels `scope` under starter; partial HS/relay wire then `started=false` allows overlapping second `start`. Control `SIGNAL DORMANT` can interleave.
- **Fix**: Lifecycle enum + CAS on stop; abort start must not leave `started=true`; join child jobs before clearing flag.
- **Related**: CF-002, CF-007, RET-001 engine teardown.

### [CF-007] Dormant check-then-act (soft gate TOCTOU) — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High — softest in cap)
- **Evidence**: `TorClient.kt:187` (`if (dormant) error`) then work; `:414-419` (`@Volatile var dormant`); `OnionTunnel.kt:87-88` + `:167-175` (scaffolding + `setDormant`); RET-008 silent `runCatching` on SetDormant
- **Risk**: High
- **Exploit logic**: Observe `dormant==false`, open stream; concurrent `signalDormant()` — stream still builds. Split-brain: scaffolding dormant vs `TorClient.dormant` if only one updated. Soft dormant does not tear down existing streams.
- **Fix**: Generation counter or mutex with connect; single choke point; document intentional soft semantics.
- **Related**: CF-006, RET-008.

### [CF-008] ConcurrentHashMap check-then-act clusters — **OPEN**
- **Track**: controlflow
- **Status**: OPEN (High) — Fake-IP **cap** FIXED (MEM-001); TOCTOU residual
- **Evidence**:
  - Keypin: `KeypinAndConsDiff.kt:36-54` (`check` then dual `byRsa`/`byEd` puts — two conflicting pairs can both ADD); caller swallows Result (RET-005)
  - Fake-IP: `FakeIpDnsCookies.kt:40-62` (lookup / `containsKey` then insert — dual hosts same cookie possible under race); MEM-001 caps+prune landed
  - HsCache: `HsCache.kt:45-55`, `:143-167` (non-atomic `allocatedBytes` with CHM entries)
- **Risk**: High
- **Exploit logic**: Classic TOCTOU. Dirauth keypin can pin inconsistent RSA↔Ed maps; fake-IP can hand two hosts one cookie; cache accounting drifts → bad OOM trim.
- **Fix**: `compute`/`putIfAbsent` with conflict return; Keypin under one lock or composite key; `AtomicLong` for `allocatedBytes` inside map compute.
- **Related**: CF-004, CF-005, RET-005, MEM-001 FIXED residual.

---

## Conflicts

Cross-checks vs mailbox `/tmp/ktor-safety-pass/{return,type,bounds,memory,io,cpu}.md` + in-repo `failure.md`:

| Clash | Domains | Resolution |
| --- | --- | --- |
| ID alias “CF-001” = engine teardown | FAIL/MEM/SAFETY_AUDIT vs this file | **This domain:** CF-001 = OR handshake; engine lifecycle = **CF-002**. Peer docs that say “CF-001 teardown” mean CF-002 / RET-001. |
| Teardown + scope recreate | RET-001 **FIXED**, CF-002 OPEN, FAIL-001 stale, MEM-007 | Teardown/recreate landed; **do not** mark CF-002 FIXED — race on `running` / non-CAS stop remains. |
| CERTS soft-null vs FSM | RET-006 OPEN, TYP-006, CF-001 | Hard-fail CERTS parse + require CERTS before NETINFO; soft null enables identity skip. |
| AUTH verify ignored | RET-003 OPEN, BND-004, CF-001 / CF-009 | Enforcing verify is CF auth-workflow; bounds alone insufficient. |
| Keypin Result swallow vs TOCTOU | RET-005, CF-008 | Fix swallow **and** atomic check-and-add together. |
| Fake-IP cap vs insert race | MEM-001 FIXED, CF-008 | Cap≠atomic insert; compose eviction with `putIfAbsent`. |
| Engine ANR vs fail-closed stop | CPU-004, CF-002 | Async stop OK if CAS lifecycle preserved; do not skip teardown. |
| Listener cancel vs accept-after-close | IO-007/008, CF-002 | Close sockets in `finally` then cancel; stop/start race amplifies FD / accept-after-close. |
| EXTEND OOB vs EXTEND race | BND-001/002, CF-009 | Length checks ≠ serialize extend vs DESTROY; both required. |
| ADD_ONION OK before publish | RET-007, CF-003 | Control lies about HS ready while intro FSM ungated — fix both. |
| FAIL-001 “no teardown” | failure.md vs code | **Stale** — prefer RET-001 / current `KotlinTorEngine`; CF keeps race OPEN. |

## Mailbox

Read at pass start: `README.txt` + peer drops `return.md`, `type.md`, `bounds.md`, `memory.md`, `io.md`, `cpu.md`. FAIL not in mailbox — used `docs/safety/domains/failure.md` (pre-fix claims). Wrote this file to repo + `/tmp/ktor-safety-pass/controlflow.md`.

## Out of scope / deferred (not counted)

- Circpad / Conflux FSMs, guard reachability FSM.
- Medium: `RelayService.@Volatile running` accept loop; `OnionServiceManager.running` unsynchronized list; `OrConnection.close` idempotent but not CAS (double-close mostly safe).
- Control AUTHENTICATE FSM itself is largely gated (`expectAuthenticateNext`) — residual NULL-auth is CRY/FAIL, not CF reopen.
