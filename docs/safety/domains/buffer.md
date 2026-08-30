# Domain: buffer

**Scope:** MTU/cell receive buffers, `ByteArray`/`StringBuilder`/`ArrayList<Byte>` growth, UnparseableDump, directory document assembly, stream RELAY DATA coalescing, SOCKS/HTTP header/body caps, control-line / HSPOST bodies, stream splice, cell buffer reuse/aliasing, DNS response builders.  
**Main sources:** `:core` (`cell`, `circuit`, `link`, `dir`, `compress`, `net`, `relay`, `crypto/CgoHop`), `:proxy` (`DnsPortServer`), `:control` (`ControlServer`).  
**Pass:** 2026-08-03 · mailbox `/tmp/ktor-safety-pass` (peers: `cpu`, `memory`, `bounds`, `io`, `return`, `type`). Cap ~8 Critical/High.

## Pass status

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| BUF-001 | **FIXED** | Low | DNSPort shared UDP buf — `copyOf` before `launch` (safe) |
| BUF-002 | **OPEN** | Medium | UnparseableDump body capped; tag map unbounded |
| BUF-003 | **OPEN** | **High** | BEGIN_DIR `StringBuilder` appends RELAY DATA with no size cap |
| BUF-004 | **OPEN** | **High** | Stream inbound `Channel.UNLIMITED` + one-cell `read()` — no coalesce/backpressure |
| BUF-005 | **OPEN** | **High** | `TorCompress.uncompress` / dir inflate grow unbounded; `isCompressionBomb` unused |
| BUF-006 | **OPEN** | Medium | TUN MTU / `MemoryTun` silent truncate on oversize packet |
| BUF-007 | **OPEN** | Medium | Cell/`OrChannel` `copyOf` amplify; `appendIn` has no `MAX_INBUF` |
| BUF-008 | **OPEN** | **High** | `ArrayList<Byte>` framing (`readHttpResponse`, SOCKS UDP, HTTP head) O(n²) + box |
| BUF-009 | **NEW** | **High** | Control `BufferedReader.readLine` + HSPOST body uncapped |
| BUF-010 | **NEW** | **High** | SOCKS4 userid/domain `ArrayList` loops uncapped; TLS SNI `readFully(recLen)` |

**Counts:** FIXED **1** · OPEN **7** · NEW **2**.  
**Critical/High open+new (capped):** BUF-003, BUF-004, BUF-005, BUF-008, BUF-009, BUF-010 (6).  
**Top 3 open BUF IDs:** **BUF-003** · **BUF-004** · **BUF-009**

---

## Baseline (verified safe / capped)

| Control | Status | Evidence |
|---------|--------|----------|
| DNSPort recv copy-before-launch | **OK** | `DnsPortServer.kt:48-56` — `ByteArray(512)` + `packet.data.copyOf(packet.length)` |
| DNS response builders ≤512 | **OK** | `DnsPortServer.kt:105-137` `ByteBuffer.allocate(512)`; `TunFakeDns` empty resp `copyOf(…coerceAtMost(512))` — size-safe; QNAME re-walk → BND-006 |
| DirPort HTTP headers | **OK** | `RelayService.kt:302-304` — `headerBytes` hard-stop 65536 |
| HTTP CONNECT / multilingual headers | **OK** | `ProxyFrontends.kt:56` `readHttpHead(max=64KiB)` |
| Stream splice chunk | **OK** | `StreamRelay.kt:8-44` — fixed `bufSize` default 16KiB, per-direction local `ByteArray`, no shared alias |
| Exit→circuit DATA | **OK** | `RelayService.kt:771-778` — `ByteArray(498)` + `buf.copyOf(n)` before `sendRelayData` |
| CGO peel/forward copy | **OK** | `RelayService.kt:831`, `:1089` — `payload.copyOf()` / `c.payload.copyOf()` before in-place CGO |
| LineProtocols | **OK** | `LineProtocols.kt:8-24` — `maxLine=8192` (FTP/SMTP path); **not** used by ControlServer |

---

## FIXED

### [BUF-001] DNSPort shared receive buffer copy — FIXED (safe)
- **Status**: FIXED (verified safe pattern; no remediation needed)
- **Track**: buffer
- **Evidence**: `proxy/.../DnsPortServer.kt:48-56` — single `ByteArray(512)` for `DatagramPacket`; `copyOf(packet.length)` before `launch { handleQuery }`
- **Risk**: Low
- **Fix**: Keep copy-before-launch; IO-003 in-flight semaphore remains the flood gate
- **Related**: IO-003 FIXED, IO-010 ASSOCIATE residual, BND-006

---

## OPEN / NEW

### [BUF-003] BEGIN_DIR stream `StringBuilder` unbounded — OPEN · High
- **Track**: buffer
- **Evidence**: `relay/RelayService.kt:371-373` `DirStreamState(buf: StringBuilder)`; `:570-576` every `RELAY DATA` does `ds.buf.append(...)` until `\r\n\r\n` / `\n\n` — **no** max length. Contrast DirPort HTTP `:304` (`headerBytes` hard-stop 65536)
- **Risk**: High (relay ORDir path DoS / heap blowup)
- **Fix**: Cap `ds.buf.length` (align 64KiB headers); END/DESTROY stream and drop on overflow; prefer length-checked `ByteArrayOutputStream`
- **Related**: BUF-002, MEM, BND (DirPort cap alignment)

### [BUF-004] Stream DATA: unlimited channel, no coalescing — OPEN · High
- **Track**: buffer
- **Evidence**:
  - `circuit/Circuit.kt:38,395,414,467,609` — per-stream / circuit `Channel<RelayCell>(Channel.UNLIMITED)`
  - `link/OrConnection.kt:68,112` — control/per-circ cell channels also `UNLIMITED`
  - `:154-162` inbound DATA `ch.send(relay)` with no queue bound
  - `TorStream.read()` `:725-733` returns **one** DATA cell; no merge of consecutive DATA
  - Outbound `sendData` correctly chunks at 498; inbound is the gap
- **Risk**: High (amplifies MEM-005 retained circuits holding stream channels)
- **Fix**: Bounded stream inbuf (bytes and/or cells) with SENDME/backpressure; coalesce adjacent DATA under hard max before `read()` / `BytePipe`
- **Related**: MEM-005, CircuitFlowControl / CongestionControl, IO stream close

### [BUF-005] Inflate / uncompress ByteArray growth uncapped — OPEN · High
- **Track**: buffer
- **Evidence**: `compress/TorCompress.kt:113-127` `GZIPInputStream`/`InflaterInputStream` `.use { it.readBytes() }`; `isCompressionBomb` `:140-143` exists but is **never called**. `ZstdLzmaProviders.kt:58` same `readBytes()`. `dir/DirectoryClient.kt:185-193` `httpGet` → `readBytes()`; `:196-201` `maybeInflate` → `readText()` with no output ceiling
- **Risk**: High (compression bomb / consensus fetch DoS)
- **Fix**: Stream decompress into capped buffer; refuse when `isCompressionBomb(in, out)` or out > consensus budget (e.g. 16–64 MiB); same gate for Zstd/LZMA
- **Related**: MEM-008 (stream `.use`), dir fetch path

### [BUF-008] `ArrayList<Byte>` framing / O(n²) rebuild — OPEN · High
- **Track**: buffer
- **Evidence**:
  - `circuit/Circuit.kt:737-759` — `ArrayList<Byte>()` then `for (b in chunk) out += b`; each iteration `out.toByteArray().decodeToString()` to find headers / Content-Length. Cap `maxBytes` default 512 KiB mitigates absolute size but not O(n²) copies / boxing
  - `net/FramingProtocols.kt:341-356`, `:375-385` — SOCKS UDP / UdpGw `ArrayList<Byte>` + `acc.toByteArray()` + `removeAt(0)` per frame (**CPU-005**); **no max `acc` size** while waiting for a parseable frame
  - `ProxyFrontends.kt:56-71` — `readHttpHead` uses `ArrayList<Byte>` (size-capped at 64KiB; still boxing)
- **Risk**: High (CPU thrash + unbounded accumulate on UDP-over-TCP until frame parses)
- **Fix**: `ByteArray`/`ByteArrayOutputStream` + offset; cap accumulate bytes; stop full-body `String` rebuild until complete; fix once with CPU-005
- **Related**: CPU-005 OPEN, TYP-007, BUF-004

### [BUF-009] Control line / HSPOST body uncapped — NEW · High
- **Track**: buffer
- **Evidence**:
  - `control/ControlServer.kt:113,142` — `BufferedReader.readLine()` with **no** max line length (JDK grows until `\n` or EOF)
  - `:591-609` `handleHsPost` — multiline `StringBuilder` appends every `readLine()` until `.` with **no** body/line cap
  - Contrast: `net/LineProtocols.kt:8-24` already has `maxLine=8192` for FTP/SMTP — unused here
  - Same class: `pt/ExtOrPort.kt`, `PtManager.kt` `readLine` (local PT stdout; lower exposure)
- **Risk**: High (authenticated or loopback-adjacent control DoS; remote if Control non-loopback + auth)
- **Fix**: Cap line length (e.g. 1–4 KiB control-spec practical) and HSPOST body (descriptor size budget); reject/close on overflow; reuse `LineReader`-style API
- **Related**: IO-004 FIXED (session count ≠ line size), CRY control auth, CPU-007 control regex

### [BUF-010] SOCKS4 userid/domain + TLS SNI record uncapped reads — NEW · High
- **Track**: buffer
- **Evidence**:
  - `net/ProxyFrontends.kt:189-205` — SOCKS4 userid and SOCKS4a domain accumulated in `ArrayList<Byte>` until `NUL` with **no** max length
  - `:315-317` — TLS ClientHello `recLen` (u16) then `local.readFully(recLen)` — up to 65535 bytes forced into heap before SNI parse; full record `pushFront` via `ArrayList` insert-at-0 (`:17-20`) O(n²)
- **Risk**: High (local AP DoS before route; amplify with IO-009 uncapped secondary acceptors)
- **Fix**: Cap userid/domain (e.g. 255); refuse `recLen` above ClientHello practical max (~16KiB); `pushFront` via deque/`ByteArray` prepend, not `add(0,…)`
- **Related**: IO-001 FIXED / IO-009 NEW, CPU-005, BND

### [BUF-002] UnparseableDump body capped; tag map not — OPEN · Medium
- **Track**: buffer
- **Evidence**: `core/.../dir/DirParseHelpers.kt:73-86` — `dumps[tag] = body.take(64_000)` into unbounded `ConcurrentHashMap`
- **Risk**: Medium
- **Fix**: Cap tag count (LRU/FIFO, e.g. 64); reject empty/oversized tags
- **Related**: MEM map-cap; SAFETY_AUDIT deferred “UnparseableDump caps”

### [BUF-006] TUN MTU buffer silent truncation — OPEN · Medium
- **Track**: buffer
- **Evidence**: `net/stack/TunTorBridge.kt:77-88` — reused `ByteArray(mtu.coerceAtLeast(1500)+64)`; `MemoryTun.readPacket` `:109-112` `arraycopy(..., pkt.size.coerceAtMost(buf.size))` returns truncated length without error if inject > MTU. Production path copies `buf.copyOfRange(offset, n)` after read — safe vs alias; truncate still silent
- **Risk**: Medium
- **Fix**: Drop/log when `pkt.size > buf.size`; size TUN buf from negotiated MTU; never silently shrink IP packets
- **Related**: OnionTunnel `mtu` default 1500; BND

### [BUF-007] Cell / channel ByteArray `copyOf` amplification — OPEN · Medium
- **Track**: buffer
- **Evidence**: `circuit/CircuitMux.kt:12-15` `CellQueue.append` → `payload.copyOf()` up to `DEFAULT_MAX=1024` cells/circ; `link/OrChannel.kt:80-84` `queueOut` copies under `MAX_OUTBUF` 32 MiB; `appendIn` `:110-114` copies with **no** inbuf cap (lite path / tests). Variable-cell wire read still uncapped → **BND-003** (`CellCodec.read` `readNBytes(len)` ≤65535)
- **Risk**: Medium (High when composed with BND-003 uncapped cells)
- **Fix**: Add `MAX_INBUF` mirroring outbuf; keep copy at trust boundary; lower embed `MAX_OUTBUF`
- **Related**: MEM-003, BND-003, CPU-001, KIST 514-byte cells

**Cell reuse / aliasing note:** `CgoHop` mutates caller buffers in place (`CgoHop.kt:42-52`, `:80-81`, `:104-105`); `AesCtr.processInPlace` exists (`AesCtr.kt:26-28`) but is unused on hot path. Current relay/client call sites `copyOf` before mutate — **do not** remove those copies. Sharing `Cell.payload` across queue + crypto without copy → silent corruption (latent Medium if API reused carelessly).

---

## Conflicts

Cross-checks against other domains:

| Clash | Domains | Note |
| --- | --- | --- |
| Dump/tag caps vs diagnostics | BUF-002, MEM | Prefer hard tag+body caps; diagnostics lose oldest dumps under flood — do not remove `take(64_000)` |
| Dir `StringBuilder` vs DirPort 64KiB header | BUF-003, BND | Align BEGIN_DIR cap with DirPort `:304` 65536; fail-closed END stream |
| DATA coalesce size vs latency / SENDME | BUF-004, circuit flow | Cap inbuf bytes; coalesce only within cap; do not raise `Channel.UNLIMITED` to “fix” throughput |
| Compression bomb reject vs large consensus | BUF-005, dir | Absolute out ceiling (tens of MiB) + ratio; legitimate consensuses must stay under ceiling |
| Larger TUN MTU vs MEM | BUF-006, MEM | Size buf from real MTU; drop oversize rather than allocate jumbo by default |
| Cell `copyOf` vs zero-copy | BUF-007, CPU | Keep copy at trust boundary; bound queue depth instead of sharing mutable buffers |
| DNS shared-buf copy vs UDP flood | BUF-001, IO-003 | Keep copy; IO in-flight semaphore is the DoS control |
| Variable-cell max vs BUF/MEM | BND-003, BUF-007 | Cap length (BND) before large transient alloc; fail-closed close |

## Conflicts (live)

Mailbox re-read before close: `/tmp/ktor-safety-pass/{cpu,memory,bounds,io,return,type}.md`.

| Live note | Source | Action |
| --- | --- | --- |
| CPU-005 `ArrayList<Byte>` + `removeAt(0)` **OPEN** High | `cpu.md` | Same remediation class as BUF-008; fix once (`ByteArray`+offset). Cap accumulate size in BUF; CPU owns thrash. |
| BUF Circuit `readHttpResponse` O(n²) cross-listed | `cpu.md` Conflicts (live) | Confirmed still present `Circuit.kt:737-759`; elevated BUF-008 to High this pass. |
| BUF-004 `Channel.UNLIMITED` amplifies MEM-005 | `memory.md` Conflicts (live) | Bound channels (BUF) **and** scrub circuits (MEM-005); do not close either alone. |
| UnparseableDump tags still unbounded | `memory.md` | Align BUF-002 tag cap with MEM map-cap pattern. |
| BND-003 variable-cell uncapped `readNBytes` | `bounds.md` | BUF-007 composition: length cap is BND; inbuf byte cap is BUF. Prefer fail-closed close. |
| DNS 512 buffer vs long names | `bounds.md` BND-006 | Builders stay ≤512 (BUF baseline OK); truncate/FORMERR rather than grow. |
| IO-003 DNSPort FIXED; ASSOCIATE → IO-010 NEW | `io.md` | Drop-before-`ArrayList` on DNS remains; SOCKS UDP framing O(n²)/unbounded acc still BUF-008/CPU-005. |
| IO accept caps ≠ buffer caps | `io.md` / `cpu.md` | Do not treat `ProxyAcceptLimits` as closing BUF-003/004/005/009. |
| TYP-007 `ArrayList<Byte>` wire builders | `type.md` | Coordinate typed builders with BUF-008/CPU-005; TYP owns RESOLVED/ATYP enums. |
| RET-001 FIXED teardown | `return.md` | No clash; control-line caps (BUF-009) independent of teardown order. |
| No ID renumber required | peers | BUF-001..008 stable; **NEW** BUF-009, BUF-010 this pass. |
