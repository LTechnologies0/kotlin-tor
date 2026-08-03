# Domain: bounds

**Scope:** main Kotlin — `copyOfRange` / index OOB, cell & relay payload lengths, link variable-cell sizes, DNS packet parse (`TunFakeDns` / DNSPort), unchecked array indexing on wire data.  
**Main sources:** `:core` (`cell`, `relay`, `link`, `circuit`, `net/stack`), `:proxy` (`DnsPortServer`). Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| BND-001 | **High** | `parseExtend2` indexes/`copyOfRange` with no remaining-length checks |
| BND-002 | **High** | `parseCreated2Payload` / EXTEND CREATED2 `hlen` → `copyOfRange` without size gate |
| BND-003 | **High** | `CellCodec.read` variable cells: u16 length uncapped (≤65535 alloc/read) |
| BND-004 | **High** | `OrAuthenticate.parse` `copyOfRange(4, 4+len)` without `payload.size` check |
| BND-005 | **Medium** | `RelayCell.toPayload` V0: no `length ≤ 509−11` before `copyInto` |
| BND-006 | **Medium** | `TunFakeDns.buildResponse` re-walks QNAME without bounds / `0xc0` checks |
| BND-007 | **Low** | `TunFakeDns.parseQuery` / DNSPort name walk — length checks present (keep) |
| BND-008 | **Medium** | `readU16be`/`readU32be` assume `offset+width` in-bounds (callers uneven) |

No standalone **Critical** OOB (uncaught process crash on hot path); High items are peer-driven `IndexOutOfBoundsException` / unbounded variable-cell read. Several High paths are wrapped in `try`/`runCatching` (fail to DESTROY/TRUNCATED/log) — still exception-as-control-flow, not fail-closed length validation.

---

### [BND-001] `parseExtend2` link-spec walk without remaining-length checks
- **Track**: bounds
- **Evidence**: `core/.../relay/RelayService.kt:1207-1237` — `data[i++]` for `nspec`/type/len; `data.copyOfRange(i, i + len)` and later `copyOfRange(i, i + hlen)` with no `i + … ≤ data.size` before access (contrast `LinkSpecifiers.parsePacked` which `require`s headers/bodies)
- **Risk**: High
- **Exploit logic**: Client sends peeled EXTEND2 with `nspec`/len/`hlen` past end of relay body → `IndexOutOfBoundsException` inside `handleExtend2` `try` → TRUNCATED path; still DoS of extend and noisy fail
- **Fix**: Before each read: `require(i + need <= data.size)`; reject oversized `nspec`; mirror `LinkSpecifiers.parsePacked`
- **Related**: BND-002, FAIL (exception-as-control-flow)

### [BND-002] CREATED2 / `parseCreated2Payload` trusts `hlen` for `copyOfRange`
- **Track**: bounds
- **Evidence**:
  - `circuit/CircuitCrypto.kt:205-207` — `hlen` from first two bytes; `payload.copyOfRange(2, 2 + hlen)` unchecked
  - `RelayService.kt:1070-1071` — same pattern on next-hop `CREATED2` during EXTEND2
  - Callers: `Circuit.kt:238`, `:252`, `:269` (first-hop create)
- **Risk**: High
- **Exploit logic**: Peer/next hop sets `hlen` so `2 + hlen > payload.size` (fixed cell still 509) → OOB on client bootstrap or mid-extend
- **Fix**: `require(payload.size >= 2 && hlen <= payload.size - 2)` (and optional max handshake size) before slice
- **Related**: BND-001, cell payload lengths

### [BND-003] Link variable cells: no max payload length
- **Track**: bounds
- **Evidence**: `cell/Cell.kt:63-69` — `readU16be` length then `input.readNBytes(len)` with no cap; variable cmds in `CellCommand` (VERSIONS, VPADDING, CERTS, AUTH_*, …)
- **Risk**: High
- **Exploit logic**: Peer advertises `len=65535` (e.g. VPADDING/CERTS flood) → large alloc + blocking read per cell on every OR accept path (`OrConnection.readLoop`, `RelayService` OR loop)
- **Fix**: Cap variable payload (align with C Tor / tor-spec practical max); refuse/close on oversize before `readNBytes`
- **Related**: MEM/IO OR accept, BUF

### [BND-004] `OrAuthenticate.parse` length field unchecked before slice
- **Track**: bounds
- **Evidence**: `link/OrAuthenticate.kt:120-126` — `require(payload.size >= 4)` then `copyOfRange(4, 4 + len)` without `4 + len <= payload.size`; `take(n)` later also unchecked vs remaining
- **Risk**: High
- **Exploit logic**: Initiator AUTHENTICATE variable cell with lying `len` → OOB; `RelayService.kt:451-457` catches via `runCatching` (log only)
- **Fix**: `require(4 + len <= payload.size)`; bounds inside `take`; fail-closed close link on auth parse failure
- **Related**: BND-003 (variable cell), CRY auth verify

### [BND-005] Relay V0 encode: length vs fixed cell capacity
- **Track**: bounds
- **Evidence**: `cell/Cell.kt:88-101` — `toPayload()` pads to `FIXED_PAYLOAD_LEN` but only `require(data.size <= length)`; no `length <= FIXED_PAYLOAD_LEN - 11` before `copyInto(out, 11, …)` (V1 path does check maxLen at `:116-117`)
- **Risk**: Medium
- **Exploit logic**: Mis-built `RelayCell` (length > 498) → `ArrayIndexOutOfBoundsException` on encode; parse path already checks length (`:150-151`)
- **Fix**: Same max as parse: `require(length <= Cell.FIXED_PAYLOAD_LEN - 11)`
- **Related**: cell payload lengths

### [BND-006] `TunFakeDns.buildResponse` QNAME copy without re-validation
- **Track**: bounds
- **Evidence**: `net/stack/TunFakeDns.kt:87-97` — `while` uses `len = query[i] & 0xff` then `out.put(query, i, 1 + len)` / `i += 1 + len` with no `i + 1 + len <= query.size`, no `0xc0` reject, no max labels/name (255); `ByteBuffer.allocate(512)` can `BufferOverflowException` on pathological question + AAAA answer
- **Risk**: Medium (today `handleQuery` only after `parseQuery`, which checks lengths and rejects compression — defense is call-order, not local)
- **Fix**: Reuse validated offsets from `parseQuery`, or duplicate `i + 1 + len` / compression / name-length caps; truncate safely on 512
- **Related**: BND-007, MEM-001 (fake-IP flood), IO-003

### [BND-007] DNS name parse length checks present (positive)
- **Track**: bounds
- **Evidence**:
  - `TunFakeDns.kt:36-62` — `raw.size < 12` null; `i + len > raw.size` null; compression `0xc0` null; QTYPE/QCLASS `i + 4`
  - `proxy/.../DnsPortServer.kt:89-102` — same `i + len` pattern
- **Risk**: Low (mitigated)
- **Fix**: Keep; add max labels / total name ≤ 255; ensure empty-label / missing NUL cannot fall through
- **Related**: BND-006, INT-001 (byte mask)

### [BND-008] `readU16be` / `readU32be` are unchecked helpers
- **Track**: bounds
- **Evidence**: `util/Bytes.kt:53-69` — index `buf[offset]` … `offset+width-1` with no size precondition; used on CREATE2 (`RelayService.kt:895-896` — OK when payload is fixed 509), CERTS, relay bodies, etc.
- **Risk**: Medium (depends on caller)
- **Fix**: Prefer checked helpers (`readU16beOrNull` / require size) at untrusted boundaries; audit CREATE2 path if short payloads ever constructed off wire
- **Related**: BND-001, BND-002

## Conflicts

| Clash | Domains | Note |
| --- | --- | --- |
| Variable-cell max vs CERTS/VERSIONS real size | BND-003, BUF, MEM | Cap must still allow legitimate CERTS/AUTH blobs; prefer fail-closed close over silent truncate of auth material |
| Length `require` vs exception catch | BND-001/002/004, FAIL | Prefer explicit length checks returning destroy/reject **before** `copyOfRange`; do not rely on `try`/`runCatching` as bounds mitigation |
| TunFakeDns re-walk vs parse-once | BND-006/007, MEM-001 | Validating once in `parseQuery` is fine if builders take parsed offsets only — avoid dual parsers drifting |
| Relay V0 maxLen vs DATA chunking | BND-005, relay DATA | `sendRelayData` already chunks 498 (`RelayService.kt:1133`); encode-side maxLen is belt-and-suspenders, not a throughput conflict |
| LinkSpecifiers checked vs parseExtend2 unchecked | BND-001 | Consolidate on one checked link-spec walker (HS already safer) — no conflict, dedupe |
| DNS 512 buffer vs long names | BND-006, BUF-001/002 board | Truncate/FORMERR rather than grow buffer; aligns with DNSPort 512 |
