# Domain: integer

**Scope:** main Kotlin sources (`core/`, `proxy/`, `control/`, `android`).  
**Focus:** wire-length encode truncate, CircId collision, streamId/port overflow, bandwidth/TTL/seq wrap, FakeIp / Automap octet math, accept/rate-limit Int multiply, UInt/Int casts, size+offset.  
**Pass:** 2026-08-03 re-verify · mailbox `/tmp/ktor-safety-pass` (BND/BUF/IO/MEM/TYP/RET/CPU).  
**Cap:** ~8 Critical/High.

## Pass status

| Bucket | Count | IDs |
|--------|------:|-----|
| **FIXED** | 1 | INT-001 |
| **OPEN** | 6 | INT-002 … INT-007 |
| **NEW** | 1 | INT-009 |
| **Demoted** | 1 | INT-008 → Medium (still tracked) |

**Critical/High open+new (capped 8):** INT-002 … INT-007, INT-009  
**Top 3 open INT IDs:** **INT-002**, **INT-003**, **INT-004**

---

## Critical / High summary

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| INT-001 | **FIXED** | Critical | `requireU16`/`requireU32` on `u16be`/`u32be` — no silent truncate |
| INT-002 | **OPEN** | High | `newCircId()` never retries; `registerCircuit` overwrites on collision |
| INT-003 | **OPEN** | High | Origin `nextStreamId++` unbounded; relay encodes only u16 → alias / map skew |
| INT-004 | **OPEN** | High | Ports parsed/encoded as unbounded `Int` (`toInt` / `toShort` / `u16be`) |
| INT-005 | **OPEN** | High | `parseBandwidth` Long wrap; `bandwidthKb.toInt()` advertise truncate |
| INT-006 | **OPEN** | High | `EdgeConnectionTable` keys mask streamId to u16 while Circuit uses full `Int` |
| INT-007 | **OPEN** | High | DNS / IPv4 dotted octets `toInt().toByte()` wrap without 0..255 check |
| INT-009 | **NEW** | High | HS intro rate `DosRatePerSec * 60` Int multiply wrap → `maxIntroducesPerMin` corrupt |

---

### [INT-001] Silent truncation in `u16be` / `u32be` — **FIXED**
- **Track**: integer
- **Status**: FIXED
- **Evidence**: `core/.../util/Bytes.kt` — `requireU16` / `requireU32`; `u16be`/`u32be` call them (refuse encode when out of range)
- **Risk**: was Critical
- **Related**: BND-002/003, BUF variable-cell, BND-008 unchecked reads

### [INT-002] CircId allocate without uniqueness — OPEN
- **Track**: integer
- **Evidence**: `link/OrConnection.kt:529-536` (`newCircId` random \| `0x80000000`); `:111-116` `registerCircuit` assigns `circuitChannels[circId] = ch` with no occupancy check
- **Risk**: High
- **Fix**: Retry until free (≠ 0); reject inbound CREATE if circId mapped; fail-closed on collision
- **Related**: CircuitMux.attach, relay CircState maps, CF-TOCTOU

### [INT-003] Origin streamId overflows u16 wire field — OPEN
- **Track**: integer
- **Evidence**: `circuit/Circuit.kt:39` `nextStreamId = 1`; `:394,413,466` `nextStreamId++`; `cell/Cell.kt:93-94` streamId packed as two bytes
- **Risk**: High
- **Fix**: Mask `and 0xffff`, skip 0, refuse against open streams; refuse when space exhausted (mirror `EdgeConnectionTable.allocStreamId`)
- **Related**: INT-006, RELAY demux, BUF-004 stream channels

### [INT-004] Port `Int` overflow / no 0..65535 gate — OPEN
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:345-347` `ListenSpec.parse` `toInt()`; `:675` `HiddenServicePort(vp[0].toInt(), …)`; `circuit/CircuitCrypto.kt:281` `parseBeginPayload` `toInt()`; `net/NetworkPolicy.kt:94-97`; `net/SocksCodec.kt:103-115` `putShort(e.port.toShort())`; `hs/LinkSpecifiers.kt:23` `u16be(relay.orPort)`
- **Risk**: High
- **Fix**: `requirePort` — allow `0` only for listen-auto; `1..65535` for BEGIN/HS/exit-policy; gate before `toShort`/`u16be`
- **Related**: TYP-001, IO bind, FAIL Control/Socks

### [INT-005] Bandwidth unit multiply wrap + advertise `toInt` — OPEN
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:399-409` `n * 1_000_000_000` etc. (Kotlin `Long` wraps); `relay/RelayService.kt:236` `(bandwidthRateBytes / 1000).toInt().coerceAtLeast(1)`
- **Risk**: High
- **Fix**: `Math.multiplyExact` / reject when `n > Long.MAX_VALUE / unit`; advertise with saturating `coerceAtMost(Int.MAX_VALUE.toLong()).toInt()`
- **Related**: BridgeAuth `w Bandwidth=`, descriptor bandwidth line

### [INT-006] Edge stream key masks u16; Circuit does not — OPEN
- **Track**: integer
- **Evidence**: `circuit/ConnectionEdge.kt:36-37,50` `key = (circId shl 16) or (streamId and 0xffff)`; `Circuit.kt:394+` opens with unmasked `nextStreamId++`; `allocStreamId` can yield `0` on wrap
- **Risk**: High
- **Fix**: Shared allocator; assert `streamId in 1..0xffff` at `open`/`get`; skip 0 on wrap
- **Related**: INT-003

### [INT-007] DNS / IPv4 octet wrap — OPEN
- **Track**: integer
- **Evidence**:
  - `proxy/.../DnsPortServer.kt:134` `out.put(p.toInt().toByte())` — no `0..255`
  - **Also**: `net/stack/Ipv4Packet.kt:100-104` `parseAddress`; `net/NetEndpoint.kt:59-62` same wrap
- **Risk**: High (wrong A / wrong bind address)
- **Fix**: Reject octet ∉ `0..255` before `toByte()`; keep `and 0xff` on wire→int reads
- **Related**: BND-006/007, FakeIp / Automap string IPs (generator OK; parse paths not)

### [INT-009] HS intro rate `* 60` Int wrap — NEW
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:688-690` `currentHsIntroRate = currentHsIntroDosRate * 60` (Int); fed to `HiddenServiceConfig.maxIntroducesPerMin` (`:582`); enforced in `OnionService.kt:255-256` via `HsIntroRateLimits`
- **Risk**: High (DoS-defense / accept-limit math)
- **Exploit logic**: Torrc `HiddenServiceEnableIntroDoSRatePerSec` ≳ `Int.MAX_VALUE/60` → multiply wraps → tiny/negative minute cap → rate limit useless or fail-open path depending on `> 0` check
- **Fix**: `Math.multiplyExact` / `toLong()` then `coerceIn(0, Int.MAX_VALUE)`; reject absurd torrc rates
- **Related**: IO/MEM accept caps, HS intro DoS, CPU flood

---

### [INT-008] Seq counters: Conflux Long vs TCP u32 mask — OPEN (Medium)
- **Track**: integer
- **Evidence**: `circuit/Conflux.kt:16-24` `nextSeq++` + `u64be`; TUN `TunIpStack.kt:141,148,171` masks `and 0xffffffffL` (OK); `TcpDns.kt:69` / `TcpHeader.build` `putInt(seq.toInt())` relies on caller mask
- **Risk**: Medium (demoted this pass — hot path masks; residual is API contract)
- **Fix**: Boundary `u32(seq)`; Conflux document modular u64; unit test wrap
- **Related**: FakeIp TTL `ttlCacheSec * 1000L` + `nowMs()` (`FakeIpDnsCookies.kt:59,80`) — Long add wrap → expiry skew (config-only; keep Medium)

---

## Conflicts

| Clash | Domains | Note |
| --- | --- | --- |
| Checked `requireU16` vs encode perf | INT-001, BND-003, BUF | Fail-closed on wire lengths; cap variable-cell read (BND) separately from encode check |
| CircId retry vs mux attach race | INT-002, CF | Uniqueness must be atomic with `circuitChannels` / `CircuitMux.attach` |
| Stream u16 space vs DoS | INT-003/006, MEM/CPU/IO | Hard u16 space + stream/accept caps; do not widen beyond tor-spec |
| Port `0` listen-auto | INT-004, TYP-001, IO | Allow `0` only for ephemeral bind; BEGIN/HS/exit stay `1..65535` |
| Bandwidth advertise saturate | INT-005, dir vote | Saturating `Int` must not invert relative weights |
| DNS octet check vs Automap/FakeIp | INT-007, BND-006, MEM-001 | Generators emit 0..255; validate all parse/`toByte` paths anyway |
| Intro rate vs “unlimited” (`0`) | INT-009, HS | Distinguishing wrap-negative from intentional `0 = unlimited` (`OnionService.kt:255`) is mandatory |
| INT-008 demote vs CF SWITCH | INT-008, CF | Re-raise if Conflux SWITCH ordering lands without modular compare |

## Mailbox

Read `/tmp/ktor-safety-pass/` this pass: `bounds.md` (INT-001 ↔ BND-002/003/008; INT-007 ↔ BND-006), `buffer.md` (BUF-001/004 themes), `io.md` (accept caps FIXED — not INT remediations), `memory.md` (FakeIp cap FIXED; residual flood ≠ INT), `type.md` (TYP-001 cites INT-004), `return.md`/`cpu.md` (no INT renumber clash). In-repo `buffer.md` / `bounds.md` aligned. **No FIXED INT remediations landed in sources.**
