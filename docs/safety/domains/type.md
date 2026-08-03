# Domain: type

Scope: main Kotlin (`core` / `proxy` / `control` / `android`). Focus: unsafe casts (`as` / `as?`), `Any?` bags, wrong enum/proto encodings, `ByteArray` vs `List` wire builders, `ListenSpec` misuse. Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| TYP-001 | **High** (Critical × IO-005) | `ListenSpec.parse` mishandles `unix:`, bare IPv6, flags, unbound ports |
| TYP-002 | **High** | `CircuitMux.MuxCircuit.policyData: Any?` + `as? CircEwma` erases policy type |
| TYP-003 | **High** | AUTH RSA digest API hashes SPKI; TLS exporter return forced `as ByteArray` |
| TYP-004 | **High** | Dual SUBPROTO encodings: Trunnel ASCII vs live binary `protocol_id‖cap` |
| TYP-005 | **High** | `roleSocks` positional `List` conflates dnsCrypt vs probe `ListenSpec` roles |
| TYP-006 | **High** | CERTS/TLS `as X509Certificate` / `as SSLSocket` — wrong type → silent drop |
| TYP-007 | **Medium** | `ArrayList<Byte>` wire builders + unnamed RESOLVED vs SOCKS ATYP codes |
| TYP-008 | **Medium** | `ConnectionTable` `as` after `add` + `hopKeys[fp]!!` (NUL-002) |

No standalone Critical-only type finding; strongest cluster is **High**, escalating to Critical when ListenSpec binds non-loopback / mis-parses (IO-005 / FAIL-004).

---

### [TYP-001] `ListenSpec.parse` type/shape misuse
- **Track**: type
- **Evidence**:
  - `config/TorConfig.kt:325-348` — `data class ListenSpec(host, port)`; `parse` uses `lastIndexOf(':')` then `toInt()`
  - `:342-347` — `unix:` excluded from host:port branch → falls to `ListenSpec("127.0.0.1", t.toInt())` → `NumberFormatException` on socket paths
  - Bare IPv6 (`::1`) / multi-colon hosts split on wrong colon; bracket form `[::1]:9050` only accidentally works
  - No `port in 0..65535` (INT-004); negative / oversize Int accepted into bind APIs
  - `TorConfig.kt:624-626` SocksPort strips tokens; `:631` ControlPort / `:641+` OR/ExtOR/Dir/Metrics/DNS pass raw `value` (flags → `toInt` fail or wrong host)
- **Risk**: High (Critical when mis-parse or `0.0.0.0` exposes control/proxy — IO-005 / FAIL-004)
- **Fix**: Typed parse result (`Tcp(host,port)` | `Unix(path)` | `Auto`); strip flags before parse; validate port; parse IPv6 with brackets; reject unix until AF_UNIX listeners exist
- **Related**: IO-005, INT-004, FAIL-004, ControlServer loopback gate

### [TYP-002] Circuit mux `policyData: Any?` unsafe cast bag
- **Track**: type
- **Evidence**:
  - `circuit/CircuitMux.kt:65` — `var policyData: Any? = null`
  - `:214` — `CircuitMuxPolicy.allocCircData` returns `Any?`
  - `:256` — EWMA allocates `CircEwma` as `Any`
  - `:259`, `:270` — `mc.policyData as? CircEwma ?: return` / `?: CircEwma()` — wrong/missing type silently disables EWMA or invents empty state
  - `link/OrConnection.kt:502` — `circuitMux.policy() as? EwmaCircuitMuxPolicy`
- **Risk**: High (priority inversion / unfair cell scheduling under policy swap; fail-open to FIFO/`minBy` quirks)
- **Fix**: Generic `CircuitMux<P>` or sealed `PolicyData`; typed `EwmaCircuitMuxPolicy` accessors; never `Any?` on hot path
- **Related**: CPU scheduling, CF mux attach

### [TYP-003] AUTH0003 digest / exporter return type confusion
- **Track**: type
- **Evidence**:
  - `link/OrAuthenticate.kt:79-80` — `sha256DerRsa` = `Digests.sha256(cert.publicKey.encoded)` (**SPKI** DER)
  - `link/CertsCell.kt:89-93` — live CID/SID path = SHA256 of **PKCS#1** bit string inside SPKI
  - `OrAuthenticate.kt:66-72` — reflection exporter `m.invoke(...) as ByteArray` (unchecked; non-`ByteArray` → CCE mid-handshake)
  - Live initiator uses `CertsCell.rsaIdentitySha256*` (`OrConnection.kt:305-306`); `sha256DerRsa` is still a public footgun
- **Risk**: High (wrong CID/SID if API reused; CCE aborts AUTH; type-divergent “same” digest)
- **Fix**: Delete or rename `sha256DerRsa` to call PKCS#1 path only; exporter: `as? ByteArray ?: error(...)`; single typed `RsaIdentitySha256` helper
- **Related**: RET-003 (verify ignored), CRY AUTH, CF-001 CERTS

### [TYP-004] Wrong SUBPROTO wire type (ASCII vs binary)
- **Track**: type
- **Evidence**:
  - `trunnel/TrunnelLite.kt:46-59` — `SubprotoRequestTrunnel.encode` = ASCII `Name=Ver` map (inventory claims link handshake / CREATE)
  - `circuit/CircuitExtensions.kt:115-134` — live ntor-v3 SUBPROTO = binary `protocol_id ‖ cap_number` (Relay=6 → `[0x02,0x06]`)
  - `:139-162` — decoder accepts **both** ASCII (if `=` present) and binary — ambiguous type on untrusted ext body
  - Elevation tests assert Trunnel ASCII round-trip, not wire parity with `CircuitExtensions`
- **Risk**: High (CREATE/CGO negotiation fails or mis-parses if Trunnel codec used on wire; ASCII branch on binary body with accidental `0x3D`)
- **Fix**: One codec = binary prop346; demote Trunnel ASCII to test-only / rename; reject ASCII on live path
- **Related**: Circuit CGO path, CRY handshake

### [TYP-005] `ListenSpec` role erased in `roleSocks` list
- **Track**: type
- **Evidence**:
  - `android/.../KotlinTorEngine.kt:56-58` — `dnsCryptSocksPort` = `roleSocks[0]`, `probeSocksPort` = `roleSocks[1]`
  - `:108-116` — optional `dnsCryptSocks` / `probeSocks` each `+=` into same `CopyOnWriteArrayList`
  - Probe-only start → probe appears as dnsCrypt port; dnsCrypt-only → probe getter returns `-1` correctly but indices are untyped
- **Risk**: High (OnionVPN / DNSCrypt plane binds wrong loopback port; silent role swap)
- **Fix**: Named fields / map `enum class SocksRole { DNSCRYPT, PROBE }` → server; getters read by role not index
- **Related**: NUL-004 port `-1`, FAIL engine start, IO bind

### [TYP-006] Unchecked CERTS / TLS `as` casts
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

### [TYP-007] `ByteArray` vs `List<Byte>` wire builders / address-type enums
- **Track**: type
- **Evidence**:
  - `relay/RelayService.kt:690-713` — RESOLVED built via `ArrayList<Byte>` + `+= Int` literal coerce + `byteArrayOf(...).toList()` then `toByteArray()`
  - Tor RESOLVED types `0x04`/`0x06` vs SOCKS `ATYP_IPV4=0x01` / `ATYP_IPV6=0x04` (`SocksCodec.kt:17-19`) — no shared sealed type; easy cross-protocol misuse
  - Similar `ArrayList<Byte>` builders: `circuit/CircuitCrypto.kt:215+`, `hs/OnionService.kt:79`, `net/FramingProtocols.kt:341+` (CPU-005 O(n²))
  - `Circuit.kt:434-457` `parseResolved` hard-codes magic ints (correct for Tor, untyped)
- **Risk**: Medium (wrong ATYP → empty/corrupt RESOLVED; allocation churn)
- **Fix**: `ByteArrayOutputStream` / `ByteBuffer`; `enum class ResolvedAddrType(val id: Int)`; never reuse SOCKS ATYP for relay cells
- **Related**: CPU-005, BND parseResolved TTL skip

### [TYP-008] ConnectionTable unchecked `as` + `hopKeys!!`
- **Track**: type
- **Evidence**:
  - `link/ConnectionSt.kt:184-211` — `add(...) as OrConnectionHandle` (and peers); `ConnectionCast` correctly uses `as?`
  - `TorClient.kt:107-109`, `:427-429` — `ensureHopKeys` then `hopKeys[fp]!!`
- **Risk**: Medium (CCE if `add` wrapping changes; NPE under eviction — NUL-002)
- **Fix**: Factories return concrete type without cast; `ensureHopKeys(): HopKeys`
- **Related**: NUL-002, MEM-002

## Conflicts

See board **Conflicts → From type**. Highlights:

- TYP-001 ListenSpec validation must land with IO-005 loopback / FAIL-004 control auth (do not “fix” parse by binding `0.0.0.0`).
- TYP-003 digest unification vs RET-003 verify-enforcement — same AUTH0003 path.
- TYP-004 drop ASCII SUBPROTO vs elevation tests that assert Trunnel strings — update tests to binary.
- TYP-005 named socks roles vs NUL-004 `-1` port sentinels — getters stay `-1` only when role absent.
- TYP-006 fail-closed CERTS casts vs RET-006 silent `runCatching` — prefer hard fail over soft null.
- TYP-002 typed mux policy vs CF mux attach / CPU fairness — no `Any?` “to ship faster”.
- TYP-008 / NUL-002 / MEM-002: return `HopKeys` under mutex before any cache eviction.
