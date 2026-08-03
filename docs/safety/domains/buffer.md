# Domain: buffer

**Scope:** MTU/cell receive buffers, `ByteArray`/`StringBuilder` growth, UnparseableDump, directory document assembly, stream RELAY DATA coalescing.  
**Main sources:** `:core` (`cell`, `circuit`, `link`, `dir`, `compress`, `net/stack`, `relay`), `:proxy` (`DnsPortServer`).

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| BUF-003 | **High** | BEGIN_DIR `StringBuilder` appends RELAY DATA with no size cap until headers end |
| BUF-004 | **High** | Stream inbound `Channel.UNLIMITED` + one-cell `read()` — no DATA coalesce / backpressure |
| BUF-005 | **High** | `TorCompress.uncompress` / dir inflate grow unbounded; `isCompressionBomb` unused |

---

### [BUF-001] DNSPort shared receive buffer copy (safe)
- **Track**: buffer
- **Evidence**: `proxy/.../DnsPortServer.kt:48-56` — single `ByteArray(512)` for `DatagramPacket`; `packet.data.copyOf(packet.length)` before `launch { handleQuery }`
- **Risk**: Low
- **Fix**: None required; keep copy-before-launch pattern on any shared UDP buf
- **Related**: IO-003, BND-002

### [BUF-002] UnparseableDump body capped; tag map not
- **Track**: buffer
- **Evidence**: `core/.../dir/DirParseHelpers.kt:73-86` — `dumps[tag] = body.take(64_000)` into unbounded `ConcurrentHashMap`; production `note()` mostly tests today
- **Risk**: Medium
- **Fix**: Cap tag count (LRU/FIFO, e.g. 64); reject empty/oversized tags; keep 64KB body cap
- **Related**: MEM map-cap pattern; SAFETY_AUDIT deferred “UnparseableDump caps”

### [BUF-003] BEGIN_DIR stream `StringBuilder` unbounded
- **Track**: buffer
- **Evidence**: `relay/RelayService.kt:371-373` `DirStreamState(buf: StringBuilder)`; `:570-576` every `RELAY DATA` does `ds.buf.append(...)` until `\r\n\r\n` / `\n\n` — no max length. Contrast DirPort HTTP path `:304` (`headerBytes` hard-stop 65536)
- **Risk**: High (relay ORDir path DoS)
- **Fix**: Cap `ds.buf.length` (e.g. 64KiB headers); END/DESTROY stream and drop on overflow; prefer `ByteArrayOutputStream` + length check over unbounded `StringBuilder`
- **Related**: BUF-002 (64KB diagnostic theme), MEM

### [BUF-004] Stream DATA: unlimited channel, no coalescing
- **Track**: buffer
- **Evidence**:
  - `circuit/Circuit.kt:391,410,463,605` — per-stream `Channel<RelayCell>(Channel.UNLIMITED)`
  - `:150-158` inbound DATA `ch.send(relay)` with no queue bound
  - `TorStream.read()` `:721-729` returns **one** DATA cell; no merge of consecutive DATA
  - Outbound `sendData` `:642-649` correctly chunks at 498; inbound is the gap
- **Risk**: High
- **Fix**: Bounded stream inbuf (bytes and/or cells) with SENDME/backpressure; coalesce adjacent DATA into a growable buf with hard max before delivering to `read()` / `BytePipe`
- **Related**: CircuitFlowControl / CongestionControl (window ≠ channel bound); MEM; IO stream close

### [BUF-005] Inflate / uncompress ByteArray growth uncapped
- **Track**: buffer
- **Evidence**: `compress/TorCompress.kt:113-127` `GZIPInputStream`/`InflaterInputStream` `.use { it.readBytes() }`; `isCompressionBomb` `:140-143` exists but is **never called**. `dir/DirectoryClient.kt:185-193` `httpGet` → `readBytes()` then `maybeInflate` → `readText()` with no output ceiling
- **Risk**: High
- **Fix**: Stream decompress into a capped buffer; refuse when `isCompressionBomb(in, out)` or out > consensus-size budget (e.g. 16–64 MiB); apply same gate to Zstd/LZMA providers
- **Related**: MEM, dir fetch path

### [BUF-006] TUN MTU buffer silent truncation
- **Track**: buffer
- **Evidence**: `net/stack/TunTorBridge.kt:62,77-88` — single `ByteArray(mtu.coerceAtLeast(1500)+64)` reused; `MemoryTun.readPacket` `:109-112` `arraycopy(..., pkt.size.coerceAtMost(buf.size))` returns truncated length without error if device/test injects > MTU
- **Risk**: Medium
- **Fix**: Drop/log when `n > buf.size` or `pkt.size > buf.size`; size TUN buf from negotiated MTU; never silently shrink IP packets
- **Related**: OnionTunnel `mtu` default 1500; BND

### [BUF-007] Cell / channel ByteArray `copyOf` amplification
- **Track**: buffer
- **Evidence**: `circuit/CircuitMux.kt:12-15` `CellQueue.append` → `payload.copyOf()` up to `DEFAULT_MAX=1024` cells/circ; `link/OrChannel.kt:80-84` `queueOut` copies under `MAX_OUTBUF` 32 MiB; `appendIn` `:110-114` copies with **no** inbuf cap (lite path / tests)
- **Risk**: Medium
- **Fix**: Keep per-circ cell cap; lower default `MAX_OUTBUF` for embed; add `MAX_INBUF` mirroring outbuf; avoid double-copy where ownership transfers
- **Related**: MEM-003, KIST flush budget (`KistCmuxLoad` 514-byte cells)

### [BUF-008] `readHttpResponse` boxes every byte + rebuilds String
- **Track**: buffer
- **Evidence**: `circuit/Circuit.kt:733-755` — `ArrayList<Byte>()` then `for (b in chunk) out += b`; each iteration `out.toByteArray().decodeToString()` to find headers / Content-Length. Cap `maxBytes` default 512 KiB mitigates absolute size but not O(n²) copies / boxing
- **Risk**: Medium
- **Fix**: `ByteArrayOutputStream` (or single `ByteArray` + length); parse headers once; stop copying full body into `String` until complete
- **Related**: BUF-004 (caller of per-cell `read()`)

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
