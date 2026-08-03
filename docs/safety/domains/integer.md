# Domain: integer

**Scope:** main Kotlin sources (`core/`, `proxy/`, `control/`, `android/`).  
**Focus:** signed-byte masking, bandwidth/TTL/seq overflow, CircId wrap, port `Int` overflow, `u16be`/`u32be` misuse.  
**Cap:** 8 · **Severity filter:** Critical / High only.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| INT-001 | Critical | `u16be`/`u32be` silently truncate; variable-cell & handshake lengths can lie on the wire |
| INT-002 | High | `newCircId()` never retries; `registerCircuit` overwrites on collision |
| INT-003 | High | Origin `nextStreamId++` unbounded; relay encodes only u16 → alias / map skew |
| INT-004 | High | Ports parsed/encoded as unbounded `Int` (`toInt` / `toShort` / `u16be`) |
| INT-005 | High | `parseBandwidth` Long wrap; `bandwidthKb.toInt()` advertise truncate |
| INT-006 | High | `EdgeConnectionTable` keys mask streamId to u16 while Circuit uses full `Int` |
| INT-007 | High | DNS A-record octets `toInt().toByte()` wrap without 0..255 check |
| INT-008 | High | Conflux `nextSeq++` / TCP seq: u32 wrap OK in TUN; conflux relies on signed `Long` wrap |

---

### [INT-001] Silent truncation in `u16be` / `u32be`
- **Track**: integer
- **Evidence**: `core/.../util/Bytes.kt:44-48` (`u16be` takes low 16 bits only; `u32be` → `putInt(value.toInt())`); `cell/Cell.kt:41` `u16be(cell.payload.size)` for variable cells; `relay/RelayService.kt:927,971,998,1072` `u16be(handshake/response.size)`
- **Risk**: Critical
- **Fix**: Require `value in 0..0xffff` / `0L..0xffff_ffffL` (or return `Result`); refuse encode when size > field width; prefer checked helpers (`requireU16`, `requireU32`) at every call site that writes wire lengths
- **Related**: BUF variable-cell, bounds on CREATED2/EXTENDED2

### [INT-002] CircId allocate without uniqueness
- **Track**: integer
- **Evidence**: `link/OrConnection.kt:530-536` (`newCircId` random \| `0x80000000`); `OrConnection.kt:111-116` `registerCircuit` assigns `circuitChannels[circId] = ch` with no prior-occupancy check
- **Risk**: High
- **Fix**: Retry until free (and ≠ 0); reject inbound CREATE if circId already mapped; treat wrap/collision as protocol error not silent replace
- **Related**: CircuitMux.attach same id, relay CircState maps

### [INT-003] Origin streamId overflows u16 wire field
- **Track**: integer
- **Evidence**: `circuit/Circuit.kt:39` `private var nextStreamId = 1`; `:390,409,462` `nextStreamId++`; `cell/Cell.kt:93-94,99` streamId packed as two bytes
- **Risk**: High
- **Fix**: Allocate with `AtomicInteger` and `and 0xffff`, skip 0, refuse at open streams; refuse new streams when space exhausted (mirror `EdgeConnectionTable.allocStreamId`)
- **Related**: INT-006, RELAY BEGIN/DATA demux

### [INT-004] Port `Int` overflow / no 0..65535 gate
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:345-347` `ListenSpec.parse` `toInt()`; `:675` `HiddenServicePort(vp[0].toInt(), …)`; `circuit/CircuitCrypto.kt:277-278` `parseBeginPayload` `toInt()`; `net/NetworkPolicy.kt:94-97` exit-policy ports; `net/SocksCodec.kt:103-115` `putShort(e.port.toShort())`; `hs/LinkSpecifiers.kt:23` `u16be(relay.orPort)`
- **Risk**: High
- **Fix**: Single `requirePort(p: Int): Int` (`p in 0..65535`, or `1..65535` where 0 disallowed); use at parse and before `toShort`/`u16be`
- **Related**: IO bind, BEGIN exit, HS virtual port

### [INT-005] Bandwidth unit multiply wrap + advertise `toInt`
- **Track**: integer
- **Evidence**: `config/TorConfig.kt:399-409` `n * 1_000_000_000` etc. (Kotlin `Long` wraps); `relay/RelayService.kt:236` `(bandwidthRateBytes / 1000).toInt().coerceAtLeast(1)`
- **Risk**: High
- **Fix**: `Math.multiplyExact` / checked parse with cap (e.g. `Long.MAX_VALUE / unit`); advertise with `coerceAtMost(Int.MAX_VALUE.toLong()).toInt()` only after documenting dir-spec KB/s ceiling; reject absurd torrc values
- **Related**: descriptor `bandwidth` line, BridgeAuth `w Bandwidth=`

### [INT-006] Edge stream key masks u16; Circuit does not
- **Track**: integer
- **Evidence**: `circuit/ConnectionEdge.kt:36-37,50` `key = (circId shl 16) or (streamId and 0xffff)`; `Circuit.kt:390-393` opens edge with unmasked `nextStreamId++`
- **Risk**: High
- **Fix**: One allocator (`allocStreamId`) for origin and edge table; assert `streamId in 1..0xffff` at `open`/`get`
- **Related**: INT-003

### [INT-007] DNS A-record octet wrap (signed / out-of-range)
- **Track**: integer
- **Evidence**: `proxy/.../DnsPortServer.kt:134` `out.put(p.toInt().toByte())` — no `0..255`; contrast masked reads at `:94,109,117`
- **Risk**: High (malformed / attacker-controlled name→A path emits wrong addresses)
- **Fix**: Parse octet with range check; reject answer or skip RR if any part ∉ 0..255; keep `and 0xff` on all byte→int reads (already good on query path)
- **Related**: BND-001, FakeIp / Automap string IPs

### [INT-008] Seq counters: Conflux Long vs TCP u32 mask
- **Track**: integer
- **Evidence**: `circuit/Conflux.kt:16-24` `nextSeq++` then `u64be` (`Bytes.kt:50-51`); TUN path `net/stack/TunIpStack.kt:141,148,171` uses `and 0xffffffffL` (correct u32); `net/TcpDns.kt:69-70` `putInt(seq.toInt())` relies on caller masking
- **Risk**: High if any caller feeds unmasked seq > u32 into `TcpHeader.build`; Conflux signed overflow is bit-preserving for u64 but lacks explicit modular API / tests
- **Fix**: `fun u32(seq: Long) = seq and 0xffffffffL` at TCP build boundary; Conflux `nextSequence()` document + test wrap at `ULong` semantics; never pass raw wall TTL ms into u16/u32 fields without coerce
- **Related**: RESOLVED TTL fixed 60s (`RelayService.kt:698-705`) — low risk; HsCache TTL uses `Long` (`HsCache.kt:17,100`) — OK

---

## Conflicts

- **INT-001 vs performance / “lite” codecs:** Checked `requireU16`/`requireU32` on every cell encode adds branches; still mandatory on wire lengths — fail closed over silent truncate (aligns BUF/BND).
- **INT-002 vs INT CircMux attach:** Uniqueness retry must be atomic with `circuitChannels` / `CircuitMux.attach` or CF-TOCTOU replaces one race with another.
- **INT-003/006 vs stream DoS:** Hard u16 space → need stream cap / circuit close (MEM/CPU accept caps); do not widen streamId beyond tor-spec.
- **INT-004 vs ListenSpec port 0 (auto):** `0` is valid for ephemeral bind; gate `1..65535` only for BEGIN/HS/exit-policy, allow `0` for listen-auto.
- **INT-005 vs dir-spec Bandwidth=:** Capping advertise `Int` must not invert relative weights (use saturating max consistently in vote/bridge status).
- **INT-007 vs Automap-generated IPs:** Generator already emits 0..255; keep check anyway for non-Automap cache/forward paths.
- **INT-008 vs crypto/timing:** Seq wrap tests must not weaken Conflux SWITCH ordering checks when those land (controlflow).
