# Domain: type

**Pass:** 2026-08-03 re-audit (main Kotlin `:core` / `:proxy` / `:control` / `:android`).  
**Focus:** unsafe `as`/`as?`, `Any?` bags, `ListenSpec` parse misuse, SUBPROTO dual encodings, `roleSocks` index erasure, CERTS casts, `ByteArray` vs `List` wire builders. Cap ~8 Critical/High.

## Pass status

| Bucket | IDs |
|--------|-----|
| **FIXED** | *(none)* — bind helpers/`isLoopbackHost` + hopKeys map caps are **partial mitigations only** (see OPEN notes) |
| **OPEN** | TYP-001, TYP-002, TYP-003, TYP-004, TYP-005, TYP-006, TYP-007, TYP-008 |
| **NEW** | *(none this pass)* — prior TYP-001..008 reconfirmed against current sources |

**Top 3 open (priority):** `TYP-001`, `TYP-006`, `TYP-005`

## Critical / High summary

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| TYP-001 | **OPEN** | **High** (Critical × IO-005) | `ListenSpec.parse` mishandles `unix:`, bare IPv6, flags, unbound ports |
| TYP-002 | **OPEN** | **High** | `CircuitMux.MuxCircuit.policyData: Any?` + `as? CircEwma` erases policy type |
| TYP-003 | **OPEN** | **High** | AUTH RSA digest API hashes SPKI; TLS exporter return forced `as ByteArray` |
| TYP-004 | **OPEN** | **High** | Dual SUBPROTO encodings: Trunnel ASCII vs live binary `protocol_id‖cap` |
| TYP-005 | **OPEN** | **High** | `roleSocks` positional `List` conflates dnsCrypt vs probe `ListenSpec` roles |
| TYP-006 | **OPEN** | **High** | CERTS/TLS `as X509Certificate` / `as SSLSocket` — wrong type → silent drop |
| TYP-007 | **OPEN** | **Medium** | `ArrayList<Byte>` wire builders + unnamed RESOLVED vs SOCKS ATYP codes |
| TYP-008 | **OPEN** | **Medium** | `ConnectionTable` `as` after `add` + `hopKeys[fp]!!` (NUL-002) |

No standalone Critical-only type finding; strongest cluster is **High**, escalating to Critical when ListenSpec binds non-loopback / mis-parses (IO-005 / FAIL-004).

---

### [TYP-001] `ListenSpec.parse` type/shape misuse — OPEN
- **Track**: type
- **Evidence**:
  - `config/TorConfig.kt:325-350` — `data class ListenSpec(host, port)`; `parse` uses `lastIndexOf(':')` then `toInt()`
  - `:342-348` — `unix:` excluded from host:port branch → falls to `ListenSpec("127.0.0.1", t.toInt())` → `NumberFormatException` on socket paths
  - Bare IPv6 (`::1`) / multi-colon hosts split on wrong colon; bracket form `[::1]:9050` only accidentally works
  - No `port in 0..65535` (INT-004); negative / oversize Int accepted into bind APIs
  - `TorConfig.kt` SocksPort strips isolation tokens (`tokens.first()`); ControlPort / OR/ExtOR/Dir/Metrics pass raw `value` (flags → `toInt` fail or wrong host)
  - **Partial mitigation (not FIXED):** `isLoopbackHost()` (`:328-337`) + Android `requireSafeControl` / warn-only `requireSafeListener` (`KotlinTorEngine.kt:207-221`); CLI still parses/binds via broken `parse`
- **Risk**: High (Critical when mis-parse or `0.0.0.0` exposes control/proxy — IO-005 / FAIL-004)
- **Fix**: Typed parse result (`Tcp(host,port)` | `Unix(path)` | `Auto`); strip flags before parse; validate port; parse IPv6 with brackets; reject unix until AF_UNIX listeners exist
- **Related**: IO-005, INT-004, FAIL-004, NUL-004, ControlServer loopback gate

### [TYP-002] Circuit mux `policyData: Any?` unsafe cast bag — OPEN
- **Track**: type
- **Evidence**:
  - `circuit/CircuitMux.kt:65` — `var policyData: Any? = null`
  - `:214` — `CircuitMuxPolicy.allocCircData` returns `Any?`
  - `:256` — EWMA allocates `CircEwma` as `Any`
  - `:259`, `:270` — `mc.policyData as? CircEwma ?: return` / `?: CircEwma()` — wrong/missing type silently disables EWMA or invents empty state
  - `link/OrConnection.kt:501` — `circuitMux.policy() as? EwmaCircuitMuxPolicy`
- **Risk**: High (priority inversion / unfair cell scheduling under policy swap; fail-open to FIFO/`minBy` quirks)
- **Fix**: Generic `CircuitMux<P>` or sealed `PolicyData`; typed `EwmaCircuitMuxPolicy` accessors; never `Any?` on hot path
- **Related**: CPU scheduling, CF mux attach

### [TYP-003] AUTH0003 digest / exporter return type confusion — OPEN
- **Track**: type
- **Evidence**:
  - `link/OrAuthenticate.kt:79-80` — `sha256DerRsa` = `Digests.sha256(cert.publicKey.encoded)` (**SPKI** DER)
  - `link/CertsCell.kt:89-93` — live CID/SID path = SHA256 of **PKCS#1** bit string inside SPKI
  - `OrAuthenticate.kt:66-72` — reflection exporter `m.invoke(...) as ByteArray` (unchecked; non-`ByteArray` → CCE mid-handshake)
  - Live initiator uses `CertsCell.rsaIdentitySha256*` (`OrConnection.kt:305-306`); `sha256DerRsa` is still a public footgun
- **Risk**: High (wrong CID/SID if API reused; CCE aborts AUTH; type-divergent “same” digest)
- **Fix**: Delete or rename `sha256DerRsa` to call PKCS#1 path only; exporter: `as? ByteArray ?: error(...)`; single typed `RsaIdentitySha256` helper
- **Related**: RET-003 (verify ignored), CRY AUTH, CF-001 CERTS

### [TYP-004] Wrong SUBPROTO wire type (ASCII vs binary) — OPEN
- **Track**: type
- **Evidence**:
  - `trunnel/TrunnelLite.kt:46-59` — `SubprotoRequestTrunnel.encode` = ASCII `Name=Ver` map (inventory claims link handshake / CREATE)
  - `circuit/CircuitExtensions.kt:115-134` — live ntor-v3 SUBPROTO = binary `protocol_id ‖ cap_number` (Relay=6 → `[0x02,0x06]`)
  - `:139-162` — decoder accepts **both** ASCII (if `=` present) and binary — ambiguous type on untrusted ext body
  - Elevation tests assert Trunnel ASCII round-trip (`FeatureSmokeAllElevationTest`, `ApiLoadkeyMetricsRuntimeElevationTest`), not wire parity with `CircuitExtensions`
- **Risk**: High (CREATE/CGO negotiation fails or mis-parses if Trunnel codec used on wire; ASCII branch on binary body with accidental `0x3D`)
- **Fix**: One codec = binary prop346; demote Trunnel ASCII to test-only / rename; reject ASCII on live path
- **Related**: Circuit CGO path, CRY handshake

### [TYP-005] `ListenSpec` role erased in `roleSocks` list — OPEN
- **Track**: type
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:56-58` — `dnsCryptSocksPort` = `roleSocks[0]`, `probeSocksPort` = `roleSocks[1]`
  - `:118-126` — optional `dnsCryptSocks` / `probeSocks` each `+=` into same `CopyOnWriteArrayList`
  - Probe-only start → probe appears as dnsCrypt port; dnsCrypt-only → probe getter returns `-1` correctly but indices are untyped
- **Risk**: High (OnionVPN / DNSCrypt plane binds wrong loopback port; silent role swap)
- **Fix**: Named fields / map `enum class SocksRole { DNSCRYPT, PROBE }` → server; getters read by role not index
- **Related**: NUL-004 port `-1`, FAIL engine start, IO bind

### [TYP-006] Unchecked CERTS / TLS `as` casts — OPEN
- **Track**: type
- **Evidence**:
  - `link/CertsCell.kt:43`, `:111` — `generateCertificate(...) as X509Certificate` inside `runCatching` → ClassCast → null identity (RET-006)
  - `link/OrCertMaterial.kt:147-148` — same cast on disk certs (no soft catch → hard CCE)
  - `relay/RelayService.kt:144`, `:161` — `createServerSocket() as SSLServerSocket`, `accept() as SSLSocket`
  - `link/OrConnection.kt:171` — `createSocket(...) as SSLSocket`; `:314` uses safer `as?`
  - `dir/AuthorityCert.kt:55-65` — `public as JrsaPublicKey`
- **Risk**: High (peer CERTS non-X.509 → silent missing RSA id; factory mismatch → listener death)
- **Fix**: `as? X509Certificate ?: fail-closed`; typed SSL factories returning SSL types; no identity progress without RSA_ID_X509
- **Related**: RET-006, CF-001, CRY link auth

### [TYP-007] `ByteArray` vs `List<Byte>` wire builders / address-type enums — OPEN
- **Track**: type
- **Evidence**:
  - `relay/RelayService.kt:690-713` — RESOLVED built via `ArrayList<Byte>` + `+=` + `byteArrayOf(...).toList()` then `toByteArray()`
  - Tor RESOLVED types `0x04`/`0x06` vs SOCKS `ATYP_IPV4=0x01` / `ATYP_IPV6=0x04` (`SocksCodec.kt:17-19`) — no shared sealed type; easy cross-protocol misuse
  - Similar `ArrayList<Byte>` builders: `circuit/CircuitCrypto.kt:219+`, `hs/OnionService.kt:79`, `net/FramingProtocols.kt:341+` (CPU-005 O(n²)), `Circuit.kt:738`
  - `Circuit.kt` `parseResolved` hard-codes magic ints (correct for Tor, untyped)
- **Risk**: Medium (wrong ATYP → empty/corrupt RESOLVED; allocation churn)
- **Fix**: `ByteArrayOutputStream` / `ByteBuffer`; `enum class ResolvedAddrType(val id: Int)`; never reuse SOCKS ATYP for relay cells
- **Related**: CPU-005, BND parseResolved TTL skip

### [TYP-008] ConnectionTable unchecked `as` + `hopKeys!!` — OPEN
- **Track**: type
- **Evidence**:
  - `link/ConnectionSt.kt:184-211` — `add(...) as OrConnectionHandle` (and peers); `ConnectionCast` correctly uses `as?`
  - `TorClient.kt:108-110`, `:428-430` — `ensureHopKeys` then `hopKeys[fp]!!`
  - **Partial mitigation (not FIXED):** MEM-002 hopKeys/isolatedCircuits caps landed; SAFETY_AUDIT still lists `hopKeys!!` API as deferred reshape
- **Risk**: Medium (CCE if `add` wrapping changes; NPE under eviction — NUL-002 **High**)
- **Fix**: Factories return concrete type without cast; `ensureHopKeys(): HopKeys`
- **Related**: NUL-002, MEM-002, CF-003

---

## Conflicts (live)

Mailbox `/tmp/ktor-safety-pass/` had only `README.txt` at write time (no peer pass files yet). Live cross-check against `docs/safety/domains/*.md` + `AUDIT_BOARD.md`:

| Clash | Peers | Resolution |
|-------|-------|------------|
| TYP-001 parse vs IO-005 / FAIL-004 bind+auth | io, failure, integer | Do **not** “fix” parse by binding `0.0.0.0`. Typed parse + strip flags; keep non-loopback Control auth require. INT-004: allow port `0` auto-bind only. |
| TYP-001 negative ports vs NUL-004 `-1` sentinels | null | Reject illegal listen ports in parse; keep engine unbound ports as `-1` **or** migrate getters to `Int?` together with NUL-004. |
| TYP-003 digest unify vs RET-003 AUTH verify | return, crypto | Same AUTH0003 path — enforce verify **and** single PKCS#1 digest helper; do not weaken relay AUTH. |
| TYP-004 drop ASCII vs elevation Trunnel tests | tests / circuit | Update elevation tests to binary prop346; demote ASCII Trunnel to test-only. |
| TYP-005 named socks roles vs NUL-004 | null, failure | Named fields; getters stay `-1` only when **that role** absent (probe-only must not fill dnsCrypt index). |
| TYP-006 fail-closed casts vs RET-006 soft `runCatching` | return, controlflow | Prefer hard fail / typed error over soft null identity when CERTS required (align CF-001 CERTS FSM). |
| TYP-002 typed mux vs CF attach / CPU fairness | controlflow, cpu | No `Any?` “to ship faster”; typed policy data on hot path. |
| TYP-007 `ArrayList<Byte>` vs CPU-005 / BUF | cpu, buffer | Fix O(n²) with `ByteArray`/offset builders; typed RESOLVED enum separate from SOCKS ATYP. |
| TYP-008 / NUL-002 / MEM-002 `hopKeys!!` | null, memory | **Return** `HopKeys` under same mutex as eviction; never `!!` after map get. Peer null.md/AUDIT_BOARD mis-tag Related as TYP-002 — correct id is **TYP-008**. |
| Peer ID drift | null (`Related: TYP-002` on hopKeys!!) | Treat as documentation conflict; type owns TYP-008 for `!!` / ConnectionTable casts. |
