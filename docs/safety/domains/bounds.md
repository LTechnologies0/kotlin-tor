# Domain: bounds

**Scope:** main Kotlin — `copyOfRange` / index OOB, cell & relay payload lengths, link variable-cell sizes, DNS packet parse (`TunFakeDns` / DNSPort), unchecked array indexing on wire data.  
**Main sources:** `:core` (`cell`, `relay`, `link`, `circuit`, `net/stack`), `:proxy` (`DnsPortServer`). Cap ~8.  
**Pass:** 2026-08-03 · mailbox `/tmp/ktor-safety-pass` (empty aside from README at read time).

## Pass status

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| BND-001 | **OPEN** | High | `parseExtend2` indexes/`copyOfRange` with no remaining-length checks |
| BND-002 | **OPEN** | High | EXTEND CREATED2 / client EXTENDED2 `hlen` still ungated; helper FIXED |
| BND-003 | **FIXED** | High | `CellCodec.read` caps variable cells at `Cell.MAX_VAR_CELL_PAYLOAD` (32768); oversize fail-closed |
| BND-004 | **OPEN** | High | `OrAuthenticate.parse` `copyOfRange(4, 4+len)` without `payload.size` check |
| BND-005 | **OPEN** | Medium | `RelayCell.toPayload` V0: no `length ≤ 509−11` before `copyInto` |
| BND-006 | **OPEN** | Medium | DNS `buildResponse` QNAME re-walk without bounds / `0xc0` (TUN + DNSPort) |
| BND-007 | **FIXED** | Low | `parseQuery` / DNSPort name walk — length checks verified present |
| BND-008 | **OPEN** | Medium | `readU16be`/`readU32be` assume `offset+width` in-bounds (callers uneven) |

**Counts:** FIXED **2** · OPEN **6** · NEW IDs **0** (BND-003 fixed this protect pass).  
**Top 3 open (High):** BND-001 · BND-002 · BND-004

No standalone **Critical** OOB (uncaught process crash on hot path); High items are peer-driven `IndexOutOfBoundsException` / unbounded variable-cell read. Several High paths are wrapped in `try`/`runCatching` (fail to DESTROY/TRUNCATED/log) — still exception-as-control-flow, not fail-closed length validation.

---

### [BND-001] `parseExtend2` link-spec walk without remaining-length checks — OPEN
- **Track**: bounds
- **Evidence**: `core/.../relay/RelayService.kt:1207-1237` — `data[i++]` for `nspec`/type/len; `data.copyOfRange(i, i + len)` and later `copyOfRange(i, i + hlen)` with no `i + … ≤ data.size` before access (contrast `LinkSpecifiers.parsePacked` which `require`s headers/bodies at `hs/LinkSpecifiers.kt:42-46`)
- **Risk**: High
- **Exploit logic**: Client sends peeled EXTEND2 with `nspec`/len/`hlen` past end of relay body → `IndexOutOfBoundsException` inside `handleExtend2` `try` → TRUNCATED/DESTROY path; still DoS of extend and noisy fail
- **Fix**: Before each read: `require(i + need <= data.size)`; reject oversized `nspec`; mirror `LinkSpecifiers.parsePacked`
- **Related**: BND-002, FAIL (exception-as-control-flow)

### [BND-002] CREATED2 / EXTENDED2 `hlen` → `copyOfRange` — OPEN (partial FIXED)
- **Track**: bounds
- **Evidence**:
  - **FIXED**: `circuit/CircuitCrypto.kt:205-211` — `parseCreated2Payload` now `require(payload.size >= 2)` and `require(2 + hlen <= payload.size)` before slice; first-hop create callers (`Circuit.kt` create paths) use this helper
  - **FIXED (inbound CREATE2)**: `RelayService.kt:901-905` — `4 + hlen > cell.payload.size` → DESTROY before `copyOfRange`
  - **OPEN**: `RelayService.kt:1070-1071` — mid-extend next-hop `CREATED2`: `hlen = readU16be(...)` then `copyOfRange(2, 2 + hlen)` **without** size gate
  - **OPEN (NEW evidence this pass)**: `Circuit.kt:384-385` — client EXTENDED2: `hlen` from `extended.data[0..1]` then `copyOfRange(2, 2 + hlen)` unchecked (not routed through `parseCreated2Payload`)
- **Risk**: High (residual paths)
- **Exploit logic**: Peer/next hop sets `hlen` so `2 + hlen > payload.size` → OOB on mid-extend or client EXTENDED2 parse
- **Fix**: Reuse `parseCreated2Payload` (or identical `require`) on RelayService EXTEND CREATED2 and Circuit EXTENDED2; optional max handshake size
- **Related**: BND-001, cell payload lengths, INT-001 (length field trust)

### [BND-003] Link variable cells: no max payload length — FIXED
- **Track**: bounds
- **Evidence**: `cell/Cell.kt` — `MAX_VAR_CELL_PAYLOAD=32768`; `readVariablePayload` refuses larger before `readNBytes`; unknown cmds drained then skipped
- **Risk**: High (was)
- **Fix applied**: Cap + fail-closed `IOException` on oversize; soft-skip unknown commands after draining payload
- **Related**: MEM/IO OR accept, BUF, INT-001

### [BND-003-WAS] (historical)
- **Evidence (pre-fix)**: `CellCodec.read` used uncapped u16 length then `readNBytes(len)`
- **Exploit logic**: Peer advertises `len=65535` (e.g. VPADDING/CERTS flood) → large alloc + blocking read

### [BND-004] `OrAuthenticate.parse` length field unchecked before slice — OPEN
- **Track**: bounds
- **Evidence**: `link/OrAuthenticate.kt:120-126` — `require(payload.size >= 4)` then `copyOfRange(4, 4 + len)` without `4 + len <= payload.size`; `take(n)` later also unchecked vs remaining
- **Risk**: High
- **Exploit logic**: Initiator AUTHENTICATE variable cell with lying `len` → OOB; `RelayService.kt:451-457` catches via `runCatching` (log only — auth failure ignored)
- **Fix**: `require(4 + len <= payload.size)`; bounds inside `take`; fail-closed close link on auth parse failure
- **Related**: BND-003 (variable cell), CRY auth verify, RET (ignored auth verify)

### [BND-005] Relay V0 encode: length vs fixed cell capacity — OPEN
- **Track**: bounds
- **Evidence**: `cell/Cell.kt:88-101` — `toPayload()` pads to `FIXED_PAYLOAD_LEN` but only `require(data.size <= length)`; no `length <= FIXED_PAYLOAD_LEN - 11` before `copyInto(out, 11, …)` (V1 path does check maxLen at `:116-117`)
- **Risk**: Medium
- **Exploit logic**: Mis-built `RelayCell` (length > 498) → `ArrayIndexOutOfBoundsException` on encode; parse path already checks length (`:150-151`)
- **Fix**: Same max as parse: `require(length <= Cell.FIXED_PAYLOAD_LEN - 11)`
- **Related**: cell payload lengths

### [BND-006] DNS `buildResponse` QNAME copy without re-validation — OPEN
- **Track**: bounds
- **Evidence**:
  - `net/stack/TunFakeDns.kt:87-97` — `while` uses `len = query[i] & 0xff` then `out.put(query, i, 1 + len)` / `i += 1 + len` with no `i + 1 + len <= query.size`, no `0xc0` reject, no max labels/name (255); `ByteBuffer.allocate(512)` can `BufferOverflowException` on pathological question + AAAA answer
  - **NEW evidence this pass**: `proxy/.../DnsPortServer.kt:115-120` — identical re-walk pattern after `parseQueryName`
- **Risk**: Medium (today both builders only after parsers that check lengths and reject compression — defense is call-order, not local)
- **Fix**: Reuse validated offsets from parse, or duplicate `i + 1 + len` / compression / name-length caps; truncate safely on 512
- **Related**: BND-007, MEM-001 (fake-IP flood), IO-003, INT-007 (DNSPort A octets)

### [BND-007] DNS name parse length checks present (positive) — FIXED / keep
- **Track**: bounds
- **Evidence**:
  - `TunFakeDns.kt:36-62` — `raw.size < 12` null; `i + len > raw.size` null; compression `0xc0` null; QTYPE/QCLASS `i + 4`
  - `proxy/.../DnsPortServer.kt:89-102` — same `i + len` pattern
- **Risk**: Low (mitigated) — **Status FIXED** (control verified this pass; no regression)
- **Fix**: Keep; add max labels / total name ≤ 255; ensure empty-label / missing NUL cannot fall through
- **Related**: BND-006, INT-001 (byte mask)

### [BND-008] `readU16be` / `readU32be` are unchecked helpers — OPEN
- **Track**: bounds
- **Evidence**: `util/Bytes.kt:53-69` — index `buf[offset]` … `offset+width-1` with no size precondition; used on CREATE2 (`RelayService.kt:895-896` — OK when payload is fixed 509), CERTS, relay bodies, EXTEND2 after walk (`:1230-1232` — OOB if BND-001 leaves `i` past end), VERSIONS (`OrConnection.kt:235` — OK via `i + 1 < size` loop)
- **Risk**: Medium (depends on caller)
- **Fix**: Prefer checked helpers (`readU16beOrNull` / require size) at untrusted boundaries; audit CREATE2 path if short payloads ever constructed off wire
- **Related**: BND-001, BND-002, INT-001

## Conflicts

| Clash | Domains | Note |
| --- | --- | --- |
| Variable-cell max vs CERTS/VERSIONS real size | BND-003, BUF, MEM, INT-001 | Cap must still allow legitimate CERTS/AUTH blobs; prefer fail-closed close over silent truncate of auth material |
| Length `require` vs exception catch | BND-001/002/004, FAIL | Prefer explicit length checks returning destroy/reject **before** `copyOfRange`; do not rely on `try`/`runCatching` as bounds mitigation |
| TunFakeDns / DNSPort re-walk vs parse-once | BND-006/007, MEM-001, INT-007 | Validating once in parse is fine if builders take parsed offsets only — avoid dual parsers drifting; DNSPort A-octet wrap is INT not BND |
| Relay V0 maxLen vs DATA chunking | BND-005, relay DATA | `sendRelayData` already chunks 498 (`RelayService.kt:1133`); encode-side maxLen is belt-and-suspenders, not a throughput conflict |
| LinkSpecifiers checked vs parseExtend2 unchecked | BND-001 | Consolidate on one checked link-spec walker (HS already safer) — no conflict, dedupe |
| DNS 512 buffer vs long names | BND-006, BUF-001/002 board | Truncate/FORMERR rather than grow buffer; aligns with DNSPort 512 |
| Auth parse OOB vs ignored verify | BND-004, RET-003, CRY | Mailbox `return.md`: RET-003 `OrAuthenticate.verify` Boolean ignored — bounds fix alone insufficient if AUTHENTICATE failure stays log-only |

## Mailbox

Read `/tmp/ktor-safety-pass/` at pass start: `README.txt` only. Re-read before close: peers dropped `return.md` (RET-003 confirms BND-004 auth fail-open) and `type.md` (no direct BND clash). Also cross-checked in-repo `integer.md` INT-001/007, `buffer.md` BUF-001, `failure.md` exception-as-control.
