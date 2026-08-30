# Safety audit board (consolidated)

**Repo:** kotlin-tor · **Status:** 0.1.0-SNAPSHOT · **Pass:** 2026-08-03  
**Sources:** `/tmp/ktor-safety-pass/*.md` (12 domain mailboxes) + `docs/safety/domains/*.md`  
**Detail:** per-domain reports in [domains/](domains/) · narrative: [SAFETY_AUDIT.md](SAFETY_AUDIT.md)

> Honest scope: **not** C Tor parity, anonymity certification, or a completed third-party review.

---

## Executive counts

Sum of each domain’s reported FIXED / OPEN / NEW (aliases counted once per domain that owns an ID; see [Conflicts](#conflicts) for cross-domain canonical IDs).

| Domain | FIXED | OPEN | NEW | Notes |
|--------|------:|-----:|----:|-------|
| memory | 3 | 5 | 2 | MEM-001/002/006 FIXED |
| io | 5 | 4 | 1 | IO-001..004 + IO-009 FIXED; IO-010 NEW |
| cpu | 1 | 7 | 0 | CPU-002 FIXED (full KIST opt-in; default KIST_LITE/VANILLA) |
| type | 0 | 8 | 0 | |
| return | 2 | 6 | 0 | RET-001/002 FIXED |
| bounds | 1 | 7 | 0 | BND-007 FIXED; BND-002 partial |
| crypto | 3 | 5 | 1 | CRY-007/008/009 FIXED; CRY-010 NEW |
| buffer | 1 | 7 | 2 | BUF-009/010 NEW |
| null | 1 | 7 | 0 | NUL-008 FIXED |
| integer | 1 | 6 | 1 | INT-001 FIXED; INT-009 NEW |
| failure | 4 | 5 | 1 | FAI-001/002/003/009 FIXED; FAI-010 NEW (`FAIL-*` ≡ `FAI-*`) |
| controlflow | 2 | 6 | 1 | CF-001/002 FIXED; CF-009 NEW |
| **TOTAL** | **24** | **73** | **9** | **106** tracked domain rows |

**Unique Critical still OPEN (after alias merge):** *(none of the prior Critical queue — RET-002, CF-001, FAI-002, CPU-002, IO-009, INT-001, CF-002 FIXED this pass)*

---

## Per-domain summary tables

### memory

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| MEM-001 | High | **FIXED** | FakeIpDnsCookies capped + host↔IP prune on expiry/evict |
| MEM-002 | High | **FIXED** | hopKeys (512) / isolatedCircuits (128) capped |
| MEM-003 | High | OPEN | ConnectionTable has no ConnLimit |
| MEM-004 | Medium | OPEN | HsCache intro/dirConn unbounded; `cleanAs*` unscheduled |
| MEM-005 | High | OPEN | `Circuit.close` leaves CircuitList / open / PathBias / OR map |
| MEM-006 | High | **FIXED** | `socketProtector` cleared on engine/`stopVpn` |
| MEM-007 | Medium | OPEN | Dual VpnService scope + DirAuth orphan default scopes |
| MEM-008 | Medium | OPEN | Missing `.use` on cert / inflate streams |
| MEM-009 | High | **NEW** | OnionClient `ed25519ByFp` HSDir cache unbounded (+ disk TSV) |
| MEM-010 | Medium | **NEW** | PathSelector.families grows after hopKeys eviction |

### io

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| IO-001 | Critical | **FIXED** | SOCKS5 accept gated by `ProxyAcceptLimits` |
| IO-002 | Critical | **FIXED** | HTTP CONNECT accept gated |
| IO-003 | Critical | **FIXED** | DNSPort UDP in-flight semaphore (ASSOCIATE → IO-010) |
| IO-004 | High | **FIXED** | ControlServer session semaphore (32) |
| IO-005 | High | OPEN | Non-loopback Socks/HTTP/DNS/CLI still bind as-is (Control gate landed) |
| IO-006 | High | OPEN | Control cookie default perms; `CookieAuthFile` ignored |
| IO-007 | High | OPEN | Handler cancel skips socket close (`Exception`-only catch) |
| IO-008 | Medium | OPEN | `stop()` closes listener only; in-flight sockets rely on cancel |
| IO-009 | Critical | **FIXED** | Secondary AP acceptors capped (`ProxyAcceptLimits` on Trans/UdpGw/Ftp/Bilingual/FixedTor) |
| IO-010 | High | **NEW** | SOCKS UDP ASSOCIATE clearnet relay uncapped flood |

### cpu

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| CPU-001 | High | OPEN | Per-cell multi-hop peel/encrypt with no crypto budget |
| CPU-002 | Critical | **FIXED** | Full KIST python3 probe opt-in only (`KOTLIN_TOR_KIST_PYTHON`); default KIST_LITE/VANILLA |
| CPU-003 | High | OPEN | OR write-budget soft-spin under `writeMutex` |
| CPU-004 | High | OPEN | Engine/`VpnService` teardown sync on caller (often Main) |
| CPU-005 | High | OPEN | SOCKS UDP `ArrayList<Byte>` + `removeAt(0)` → O(n²) |
| CPU-006 | Medium | OPEN | Hot parsers recompile `Regex` per line/token |
| CPU-007 | Medium | OPEN | Untrusted text × regex → ReDoS-class CPU |
| CPU-008 | Medium | OPEN | Soft busy-waits (StreamShaper / AddressSet / PT poll) |

### type

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| TYP-001 | High | OPEN | `ListenSpec.parse` mishandles unix:/IPv6/flags/ports |
| TYP-002 | High | OPEN | CircuitMux `policyData: Any?` unsafe cast bag |
| TYP-003 | High | OPEN | AUTH RSA digest hashes SPKI; exporter forced `as ByteArray` |
| TYP-004 | High | OPEN | Dual SUBPROTO encodings (Trunnel ASCII vs live binary) |
| TYP-005 | High | OPEN | `roleSocks` positional list conflates dnsCrypt vs probe |
| TYP-006 | High | OPEN | CERTS/TLS unchecked `as` → silent identity drop |
| TYP-007 | Medium | OPEN | `ArrayList<Byte>` wire builders; RESOLVED vs SOCKS ATYP |
| TYP-008 | Medium | OPEN | ConnectionTable `as` after add; `hopKeys[fp]!!` |

### return

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| RET-001 | Critical | **FIXED** | `teardownPartialStart()` stops listeners + daemon |
| RET-002 | Critical | **FIXED** | Fail-closed OR/PT dial when `protectSocket` returns `false` (VPN/TUN) |
| RET-003 | High | OPEN | `OrAuthenticate.verify` Boolean ignored |
| RET-004 | High | OPEN | Relay TLS `startHandshake` in silent `runCatching` |
| RET-005 | High | OPEN | `Keypin.checkAndAdd` Result swallowed |
| RET-006 | High | OPEN | CERTS parse soft-fails → null identity |
| RET-007 | High | OPEN | `ADD_ONION` 250 OK before publish succeeds |
| RET-008 | Medium | OPEN | OnionTunnel refresh/dormant silent `runCatching` |

### bounds

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| BND-001 | High | OPEN | `parseExtend2` no remaining-length checks |
| BND-002 | High | OPEN | Mid-extend CREATED2 / client EXTENDED2 `hlen` ungated (helper FIXED) |
| BND-003 | High | OPEN | Variable cells: u16 length uncapped before `readNBytes` |
| BND-004 | High | OPEN | `OrAuthenticate.parse` length unchecked before slice |
| BND-005 | Medium | OPEN | Relay V0 encode missing `length ≤ 509−11` |
| BND-006 | Medium | OPEN | DNS `buildResponse` QNAME re-walk without local bounds |
| BND-007 | Low | **FIXED** | DNS name parse length checks present (keep) |
| BND-008 | Medium | OPEN | `readU16be`/`readU32be` unchecked helpers |

### crypto

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| CRY-001 | High | OPEN | Control NULL / any-password when cookie+hash unset |
| CRY-002 | High | OPEN | Wire AUTH/MAC/KH use `contentEquals` (not CT) |
| CRY-003 | High | OPEN | Ephemeral DH/seed material not wiped after handshake |
| CRY-004 | Medium | OPEN | CreateFast still client-callable; relay always accepts |
| CRY-005 | Medium | OPEN | `secureWipe` = `fill(0)`; hop AES/CGO lack destroy |
| CRY-006 | Medium | OPEN | Cookie heap not wiped; 32-byte length not enforced |
| CRY-007 | Low | **FIXED** | Control COOKIE/SAFECOOKIE/S2K use `constantTimeEquals` |
| CRY-008 | Low | **FIXED** | Handshake/cookie RNG via `SecureRandomSource` OK |
| CRY-009 | High | **FIXED** | OR keypin: require CERTS + fail if FP null/mismatch; type-2/4 extract hard-fail |
| CRY-010 | High | **NEW** | Relay `OrAuthenticate.verify` ignored (≡ RET-003) |

### buffer

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| BUF-001 | Low | **FIXED** | DNSPort shared UDP buf — copy before `launch` |
| BUF-002 | Medium | OPEN | UnparseableDump tag map unbounded |
| BUF-003 | High | OPEN | BEGIN_DIR `StringBuilder` uncapped until headers end |
| BUF-004 | High | OPEN | Stream inbound `Channel.UNLIMITED`; no DATA coalesce |
| BUF-005 | High | OPEN | Inflate/uncompress uncapped; `isCompressionBomb` unused |
| BUF-006 | Medium | OPEN | TUN MTU silent truncate on oversize |
| BUF-007 | Medium | OPEN | Cell/`OrChannel` `copyOf` amplify; no `MAX_INBUF` |
| BUF-008 | High | OPEN | `ArrayList<Byte>` framing O(n²) + boxing |
| BUF-009 | High | **NEW** | Control `readLine` + HSPOST body uncapped |
| BUF-010 | High | **NEW** | SOCKS4 userid/domain loops uncapped; TLS SNI `readFully` |

### null

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| NUL-001 | High | OPEN | Optional hop ed25519 → silent ntor-v3 downgrade |
| NUL-002 | High | OPEN | `hopKeys[fp]!!` after ensure (eviction amplifies NPE) |
| NUL-003 | High | OPEN | HS wired to `consensusOrNull()`; DoS apply no-ops on null |
| NUL-004 | High | OPEN | Port `-1` / `protect(-1)` sentinel misuse |
| NUL-005 | High | OPEN | HSDir HTTP uses `dirPort` often `0` → `host:0` |
| NUL-006 | High | OPEN | `OrConnection` force-unwraps nullable streams |
| NUL-007 | High | OPEN | Nullable or/dir/address → fabricated listen/publish defaults |
| NUL-008 | High | **FIXED** | Partial-start teardown nulls listeners + stops daemon |

### integer

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| INT-001 | Critical | **FIXED** | `requireU16`/`requireU32` on `u16be`/`u32be` (no silent truncate) |
| INT-002 | High | OPEN | `newCircId()` never retries; register overwrites |
| INT-003 | High | OPEN | Origin `nextStreamId++` unbounded vs u16 wire |
| INT-004 | High | OPEN | Ports parsed/encoded as unbounded `Int` |
| INT-005 | High | OPEN | Bandwidth Long wrap; advertise `toInt` truncate |
| INT-006 | High | OPEN | Edge table masks streamId u16; Circuit uses full Int |
| INT-007 | High | OPEN | DNS A octets `toInt().toByte()` without 0..255 |
| INT-008 | Medium | OPEN | Conflux/TCP seq wrap (demoted from High; still tracked) |
| INT-009 | High | **NEW** | HS intro `DosRatePerSec * 60` Int multiply wrap |

### failure (`FAI-*`; alias `FAIL-*`)

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| FAI-001 | Critical | **FIXED** | Partial-start teardown (`teardownPartialStart`) ≡ RET-001 |
| FAI-002 | Critical | **FIXED** | `bootstrapped`/`onReady` gated on circuit `DONE` (`isBootstrapped` ≥ 100) |
| FAI-003 | High | **FIXED** | Engine path clears sticky `started` via teardown |
| FAI-004 | High | OPEN | Control `METHODS=NULL` fail-open ≡ CRY-001 |
| FAI-005 | High | OPEN | SOCKS/HTTP accept with no bootstrap/`DONE` gate |
| FAI-006 | High | OPEN | TUN `markBootstrapped()` ignores client readiness |
| FAI-007 | Medium | OPEN | SafeSocks default off; VPN `allowIpLiterals` bypass |
| FAI-008 | Medium | **FIXED** | `isBootstrapped` now means circuit `DONE` (was descriptors) |
| FAI-009 | Critical | **FIXED** | Protect fail-closed — **canonical RET-002** |
| FAI-010 | High | **NEW** | No daemon crash recovery; sticky `started` on raw start throw |

### controlflow

| ID | Risk | Status | One-line |
|----|------|--------|----------|
| CF-001 | Critical | **FIXED** | OR handshake requires CERTS; identity pin hard-fail on null/mismatch |
| CF-002 | Critical | **FIXED** | Engine lifecycle IDLE\|STARTING\|RUNNING\|STOPPING + CAS stop ownership |
| CF-003 | High | OPEN | HS intro FSM not a gate for INTRODUCE2 |
| CF-004 | High | OPEN | Mutable intro FSM cells in ConcurrentHashMap |
| CF-005 | High | OPEN | ReplayCache horizon refresh non-atomic → dual INTRODUCE2 |
| CF-006 | High | OPEN | TorDaemon `started` stop without ownership CAS |
| CF-007 | High | OPEN | Soft dormant check-then-act admits streams after DORMANT |
| CF-008 | High | OPEN | CHM TOCTOU: Keypin / Fake-IP / HsCache `allocatedBytes` |
| CF-009 | High | **NEW** | Relay EXTEND2 async vs DESTROY / orphan CircState |

---

## Conflicts

Cross-domain clashes resolved to a **single canonical ID** where possible. Peers may still cite aliases; prefer the canonical row for remediation ownership.

### 1. RET ↔ FAI ↔ CRY (auth / protect / teardown)

| Topic | Canonical | Aliases | Resolution |
|-------|-----------|---------|------------|
| Partial-start teardown | **RET-001** | FAI-001, NUL-008, FAIL-001 | **FIXED** — `teardownPartialStart` + `ensureScope`; do not reopen as Critical |
| VPN protect fail-open | **RET-002** | FAI-009 | **FIXED** — fail-closed when protector set; MEM-006 clear-on-stop complementary |
| Relay AUTH0003 verify ignored | **RET-003** | CRY-010 | **OPEN High** — close link on `!ok`; orthogonal to control NULL |
| Control NULL AUTH | **CRY-001** | FAI-004, FAIL-004 | **OPEN High** — IO Control non-loopback gate landed; NULL still in `ControlServer` for cookie+hash off |
| CERTS soft-null / keypin skip | **CF-001** | CRY-009, RET-006, TYP-006 | **FIXED** — require CERTS + hard-fail type-2/4 parse; pin required when expected |

### 2. CF naming (do not confuse)

| ID | Means | Not |
|----|-------|-----|
| **CF-001** | OR link handshake FSM / CERTS optional | Engine teardown (that is **CF-002** / RET-001) |
| **CF-002** | `KotlinTorEngine` stop↔start race | Permanent “stop kills restart” (mitigated by `ensureScope`) |
| Stale “CF-001 teardown” in older notes | → treat as **CF-002** / **RET-001** | |

### 3. MEM × IO accept caps

| Clash | Resolution |
|-------|------------|
| `ProxyAcceptLimits` vs `ConnectionTable` ConnLimit | Prefer **both**: fail-closed refuse at accept (**IO-001..004 FIXED**) **and** ConnLimit on `ConnectionTable.add` (**MEM-003 OPEN**) |
| Uncapped secondary AP | Do not reopen IO-001..004; **IO-009 FIXED** (TransPort/UdpGw/Ftp/Bilingual/FixedTor capped) |
| DNSPort flood vs FakeIp | IO-003 FIXED + MEM-001 FIXED; ASSOCIATE residual = **IO-010**; CF-008 still needs atomic Fake-IP insert |

### 4. SAFETY_AUDIT / FAI-002 naming

Prior executive text labeled “IO-005 / FAIL-002” for **Control non-loopback auth**. That remediation is the **Control bind gate** (IO-005 Control half + engine `requireSafeControl`) — **not** **FAI-002** (bootstrap/`onReady` before `DONE` — **FIXED** this pass).

### 5. Other settled clashes

| Clash | Canonical fix order |
|-------|---------------------|
| Teardown cancel vs FD leak | IO-007/008 first (`finally` close) then aggressive cancel (RET/CF) |
| Keypin swallow vs TOCTOU | RET-005 + CF-008 together; reject CONFLICT over “liveness” |
| hopKeys cap vs `!!` | MEM-002 FIXED amplifies **NUL-002**; return `HopKeys` under same lock |
| Constant-time vs CPU | Prefer CT for secrets (CRY-002); cost ≪ CPU-002 python fork |
| KIST accuracy vs spawn | Native/cached TCP_INFO; never block `writeMutex` on subprocess (CPU-002/003) |
| Variable-cell cap vs CERTS size | BND-003 / INT-001: fail-closed close; allow legitimate CERTS/AUTH max |
| BEGIN_DIR vs DirPort 64KiB | BUF-003 align with DirPort header hard-stop |
| NULL vs control-spec | Spec allows NULL; safety = bind policy + refuse remote NULL (CRY-001 / IO-005) |

---

## Priority remediation queue

Critical first, then High. Top actionable items with related IDs. Ownership = canonical ID.

| # | Pri | Canonical | Action | Related |
|---|-----|-----------|--------|---------|
| 1 | Critical | **RET-002** | **FIXED** — Fail-closed OR/PT dial when `protectSocket` returns `false` | FAI-009, NUL-004, MEM-006 |
| 2 | Critical | **CF-001** | **FIXED** — Require CERTS; fail if FP null/mismatch | CRY-009, RET-006, TYP-006, BND-004 |
| 3 | Critical | **FAI-002** | **FIXED** — Gate `onReady` / engine `bootstrapped` on circuit `DONE` | FAI-005, FAI-006, FAI-008 |
| 4 | Critical | **CPU-002** | **FIXED** — Default off full KIST; python TCP_INFO opt-in only | CPU-003, ChannelScheduler |
| 5 | Critical | **IO-009** | **FIXED** — `ProxyAcceptLimits` on TransPort / UdpGw / Ftp / Bilingual / FixedTor | MEM-003, IO-001, CPU-001 |
| 6 | Critical | **INT-001** | **FIXED** — Checked `requireU16`/`requireU32` on wire length encodes | BND-003, BUF |
| 7 | Critical | **CF-002** | **FIXED** — Lifecycle enum + CAS stop ownership; await start job | CF-006, CPU-004, MEM-007 |
| 8 | High | **RET-003** | Destroy link / refuse CREATE2 when `OrAuthenticate.verify` fails | CRY-010, CF-001 |
| 9 | High | **MEM-005** | On `Circuit.close`: scrub CircuitList / open / PathBias / idle OR | MEM-002 residual, BUF-004, CF-009 |
| 10 | High | **CRY-001** | Refuse Control NULL outside lab; keep non-loopback cookie/hash require | FAI-004, IO-005, IO-006 |
| 11 | High | **FAI-005** | SOCKS/HTTP refuse CONNECT until bootstrap policy satisfied | FAI-002, OnionTunnel.ready |
| 12 | High | **BND-003** | Cap variable-cell payload before `readNBytes` | INT-001, MEM/IO OR |
| 13 | High | **IO-006** | Cookie file `0600` + honor `CookieAuthFile` | CRY-006 |
| 14 | High | **BUF-003** | Cap BEGIN_DIR header buffer (64KiB); END on overflow | BUF-005, DirPort |
| 15 | High | **CF-009** | Serialize EXTEND2 vs DESTROY; re-check CircState before publish `next` | BND-001/002, MEM-005 |
| — | High | **RET-005** / **CF-008** | Reject keypin CONFLICT; atomic check-and-add | dirauth |
| — | High | **IO-007**/008 | `finally` close sockets; track accepted set on `stop` | RET-001, CPU-004 |
| — | High | **NUL-002** | `ensureHopKeys(): HopKeys`; drop `!!` | TYP-008, MEM-002 |
| — | High | **CRY-002** | `constantTimeEquals` for ntor/hs-ntor AUTH/MAC/KH | CRY-007 pattern |
| — | High | **BUF-005** | Cap decompress; call `isCompressionBomb` | MEM-008 |

---

## Fixed this pass (verified)

Do not reopen as Critical unless regression:

| Cluster | IDs | What landed |
|---------|-----|-------------|
| Accept caps | IO-001..004 | `ProxyAcceptLimits` on SOCKS / HTTP / DNSPort / Control |
| Control bind auth | IO-005 (Control half) | Non-loopback Control requires cookie or hashed password |
| Partial-start | RET-001, FAI-001, NUL-008, FAI-003 (engine) | `teardownPartialStart` + `ensureScope` / new `TorDaemon` |
| Map caps | MEM-001, MEM-002 | FakeIp maxEntries+prune; hopKeys/isolatedCircuits caps |
| Protector clear | MEM-006 | Cleared on engine stop / `stopVpn` |
| Control CT compare | CRY-007 | COOKIE / SAFECOOKIE / S2K `constantTimeEquals` |
| RNG / DNS parse | CRY-008, BND-007, BUF-001 | Verified OK / keep |

---

*Synthesis auditor · 2026-08-03 · findings only from domain mailboxes / domains — no invented IDs.*
