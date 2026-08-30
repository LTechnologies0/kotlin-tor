# Domain: crypto

**Pass:** 2026-08-03 · kotlin-tor SNAPSHOT re-audit  
**Scope:** main sources `core/` (crypto, link TLS/CERTS/AUTH, circuit hop crypto, hs ntor/descriptor), `control/` (COOKIE/SAFECOOKIE/S2K/NULL), `proxy/` (no native crypto — dials only), `android/` (control auth gate), `cli/` (debug OR).  
**Baseline verify:** Prior claim that control cookie/S2K use `constantTimeEquals` — **VERIFIED FIXED**. Cap ~8 Critical/High.

## Pass status

| Status | Count | IDs |
|--------|------:|-----|
| **FIXED** | 3 | CRY-007, CRY-008, CRY-009 |
| **STILL OPEN** | 6 | CRY-001 … CRY-006 |
| **NEW** | 1 | CRY-010 |

**Critical/High open+new (capped ≤8):** CRY-001, CRY-002, CRY-003, CRY-010 (+ Medium CRY-004/005/006 still open, not in High table).  
**Top 3 open CRY IDs:** **CRY-010**, **CRY-002**, **CRY-001**

---

## Critical / High summary

| ID | Status | Risk | One-liner |
|----|--------|------|-----------|
| CRY-001 | **OPEN** | High | Control NULL / any-password AUTHENTICATE when cookie+hash unset |
| CRY-002 | **OPEN** | High | Wire AUTH/MAC/KH/descriptor MAC use `contentEquals` (not CT) |
| CRY-003 | **OPEN** | High | Ephemeral DH/seed material not wiped after handshake |
| CRY-004 | **OPEN** | Medium | CreateFast still client-callable; relay always accepts |
| CRY-005 | **OPEN** | Medium | `secureWipe` = `fill(0)` only; hop AES/CGO keys lack destroy |
| CRY-006 | **OPEN** | Medium | Cookie heap not wiped; read path does not enforce 32-byte length |
| CRY-007 | **FIXED** | Low | Control COOKIE/SAFECOOKIE/S2K use `constantTimeEquals` |
| CRY-008 | **FIXED** | Low | Handshake/cookie RNG via `SecureRandomSource` / `SecureRandom()` OK |
| CRY-009 | **FIXED** | High | OR keypin: require CERTS + fail if FP null/mismatch; type-2/4 extract hard-fail |
| CRY-010 | **NEW** | High | Relay `OrAuthenticate.verify` result ignored (AUTH0003 log-only) |

---

### [CRY-001] Control NULL / password AUTHENTICATE fail-open — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `control/.../ControlServer.kt:266` — `METHODS=NULL` when cookie off and hashed blank
  - `:279-284` — empty `AUTHENTICATE` → `authenticated = true`
  - `:296-299`, `:346-350` — quoted/hex path grants auth whenever hash unset and cookie off
  - Default still prefers cookie (`TorConfig.kt:13` `cookieAuthentication = true`)
  - **Partial mitigation**: `android/.../KotlinTorEngine.kt:215-221` `requireSafeControl` refuses non-loopback without cookie/hash — does **not** remove NULL from `ControlServer` itself; `:cli`/core daemon can still enable NULL
- **Risk**: High (Critical if ControlPort non-loopback — IO-005 / FAIL-004)
- **Fix**: Refuse NULL outside test builds; refuse non-loopback Control without cookie or hashed password in core (mirror Android gate)
- **Related**: FAIL-004, IO-005, IO-006, RET control semantics

### [CRY-002] Handshake AUTH / MAC / KH use non-constant-time compare — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `crypto/Ntor.kt:64` — `expectedAuth.contentEquals(auth)`
  - `crypto/NtorV3.kt:135`, `:205` — AUTH and client MAC
  - `crypto/CreateFast.kt:34` — KH wire check
  - `hs/HsNtor.kt:136`, `:182` — hs-ntor AUTH / INTRODUCE2 MAC
  - `hs/HsDescriptor.kt:362` — descriptor layer MAC
  - `crypto/CgoHop.kt:65`, `:83` — CGO recognition tags (lower severity)
  - `circuit/CircuitCrypto.kt:76` — relay digest recognition (4-byte; timing less sensitive)
  - **Contrast FIXED**: control path `ControlServer.kt:316,329` + `ControlS2k.kt:55` use `constantTimeEquals`
- **Risk**: High (remote timing on circuit/HS handshakes and descriptor decrypt)
- **Fix**: Replace secret AUTH/MAC/KH compares with `constantTimeEquals`. Keep public ID/KEYID as-is or CT for uniformity
- **Related**: CRY-007 FIXED, FAIL auth, CPU-001 (do not weaken CT for speed)

### [CRY-003] Ephemeral secrets survive handshake without wipe — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `Ntor.kt:68-70` wipes `secretXy`/`secretXb`/`secretInput` but **not** `state.secretKey`, HKDF `keys`, or `Result.keySeed`
  - `NtorV3.kt:108-141` — `yx`, `bx` (on `ClientState`), `secretInput`, `clientSk` never wiped
  - `HsNtor.kt:125-137`, `:174-205` — shared secrets / seed material uncleared
  - `CreateFast.kt` / `CreateOnehop.kt` — client `x` and seed retained for GC only
  - Contrast: `NtorServer.kt:32-34` matches partial client wipe of DH products only
- **Risk**: High (heap dumps / swap / crash cores retain circuit/HS keying material)
- **Fix**: Wipe ephemeral sk, DH outputs, seeds, HKDF intermediates on success and failure; clear `ClientState`; wipe live hop keys on circuit close (CRY-005)
- **Related**: CRY-005, MEM-005 circuit teardown (close does not scrub maps — keys linger longer)

### [CRY-004] CreateFast still available (client + relay always-on) — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `crypto/CreateFast.kt` — SHA1 KDF-TOR; no DH (X‖Y over OR TLS)
  - `circuit/Circuit.kt:209-223` `createFirstHopFast`; `:937-940` when `useCreateOnehop=false`
  - `relay/RelayService.kt:482-494` handles `CREATE_FAST` unconditionally
  - `relay/RelayConfigFindAddr.kt:251` `supportsCreateFast(...) = true`
- **Risk**: Medium (legacy one-hop dir; weaker than ntor if OR TLS compromised; relay cannot refuse)
- **Fix**: Prefer CreateOnehop/ntor; gate relay `CREATE_FAST` behind config/consensus; fail closed on EXTEND carrying CreateFast
- **Related**: CreateOnehop prop364 (also non-DH but stronger KDF)

### [CRY-005] `secureWipe` + AES-CTR/CGO key destroy gaps — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `util/Bytes.kt:18-20` — `secureWipe()` only `fill(0)`
  - `crypto/AesCtr.kt:11-18` — BC SIC holds key; no destroy/wipe
  - `circuit/CircuitCrypto.kt:47-48` — hop ciphers for circuit life, no close wipe
  - `crypto/CgoHop.kt:19-33` — rotatable keys/nonce; no teardown wipe
  - `Cgo.kt` ET/PRF copy key slices without wipe after use
- **Risk**: Medium (defense-in-depth; amplifies CRY-003 / MEM-005)
- **Fix**: Wipe hop/CGO key arrays on circuit close; optional `AesCtr.close()`; CT compare for CGO tags if side channels matter
- **Related**: CRY-003, MEM-005

### [CRY-006] Control cookie bytes linger; length not enforced — **STILL OPEN**
- **Track**: crypto
- **Evidence**:
  - `TorDaemon.kt:153-155` — `SecureRandomSource.nextBytes(32)` then `Files.write`; in-memory cookie never `secureWipe`
  - `ControlServer.kt:245-248`, `:327-329` — `Files.readAllBytes`; no `cookie.size == ControlCookie.COOKIE_LEN` (32)
  - Truncated/overlong cookie → weak or length-leaking compare (`constantTimeEquals` early size exit at `Bytes.kt:26`)
- **Risk**: Medium
- **Fix**: Enforce 32-byte cookie on write and read (fail closed); wipe after HMAC; pair with IO-006 `0600` / CookieAuthFile
- **Related**: IO-006, CRY-001, CRY-007

### [CRY-007] Control secret compares constant-time — **FIXED** (re-verified)
- **Track**: crypto
- **Evidence**: `ControlServer.kt:19` import; `:316` SAFECOOKIE ClientHash; `:329` COOKIE; `ControlS2k.kt:5,55` HashedControlPassword; helper `util/Bytes.kt:22-31` (XOR-accumulate, size mismatch early-exit)
- **Risk**: Low (mitigated for control auth material)
- **Fix**: None for control; extend pattern to CRY-002
- **Related**: CRY-002 OPEN

### [CRY-008] SecureRandom usage adequate — **FIXED** / ok (re-verified)
- **Track**: crypto
- **Evidence**:
  - `SecureRandomSource` (`Bytes.kt:72-76`) — process-wide `SecureRandom()`
  - Cookie, Curve25519, CreateFast/Onehop, ControlS2k salt, OrAuthenticate rand, TorSsl `SSLContext.init(..., SecureRandom())`
  - TLS protocols pinned `TLSv1.2`/`TLSv1.3` (`OrConnection.kt:172`); **no** `enabledCipherSuites` allowlist (residual Medium under CRY-009 notes)
- **Risk**: Low on Linux/Android default providers
- **Fix**: Optional `getInstanceStrong()` / NativePRNG for `SecureRandomSource` only
- **Related**: —

### [CRY-009] OR identity pin / CERTS crypto binding — **FIXED**
- **Track**: crypto
- **Status**: FIXED (with CF-001)
- **Evidence**: Handshake requires CERTS; pin fails on null/mismatch; CertsCell hard-fails type-2/4 extract; TorSsl trust-all retained with mandatory CERTS binding comment
- **Residual**: Full prop220 signature / type-5 TLS-leaf verify still thinner; RET-006 type-1 soft path
- **Related**: CF-001 FIXED, CRY-010 OPEN

### [CRY-010] Relay AUTH0003 verify ignored — **NEW**
- **Track**: crypto
- **Evidence**: `relay/RelayService.kt:449-457` — `val ok = OrAuthenticate.verify(body, body.cidEd)` only `println`; parse failures logged; neither closes link nor blocks CREATE2 when `ok==false`. Also verifies against `body.cidEd` from the cell itself (not from prior initiator CERTS — CERTS branch `:459-461` is empty)
- **Risk**: High (forged / failing AUTHENTICATE has no crypto effect on relay accept path)
- **Fix**: Fail-closed close OR on `!ok` or parse failure; verify against Ed identity from peer CERTS + check slog/clog/tlsSecrets bindings; do not proceed to CREATE2 until auth state set
- **Related**: RET-003 (owns Boolean ignore), BND-004 (parse OOB), TYP-003, CRY-009

---

## Module notes (proxy / android / cli)

| Module | Crypto surface | Verdict |
|--------|----------------|---------|
| `proxy/` | No MAC/TLS OR crypto; SOCKS/HTTP dial | No CRY IDs |
| `android/` | `cookieAuthentication=true` defaults; `requireSafeControl` | Partial CRY-001 mitigation only |
| `cli/` | Debug OR + ntor create; uses same `OrConnection` pin | Inherits CRY-009 |

**Nonce/IV:** Tor1 `AesCtr` zero-IV is per-hop keystream (spec). HS descriptor derives IV via SHAKE; HsNtor intro AES uses zero IV with per-intro keys (rend-spec). No cross-message nonce-reuse bug found beyond “spec zero IV + unique key” model.

---

## Conflicts (live)

Read `/tmp/ktor-safety-pass/{bounds,cpu,io,memory,return,type}.md` at write time.

| Clash | Domains | Resolution |
| --- | --- | --- |
| RET-003 × CRY-010 | return, crypto | Same bug: Boolean ignore. CRY owns crypto fail-closed + CERTS-bound pubkey; RET owns “return must be enforced”. Land one fix satisfying both. |
| BND-004 × CRY-010 | bounds, crypto | Bounds-fix AUTH parse **alone** insufficient while verify stays log-only (bounds.md Conflicts). |
| CF-001 / RET-006 × CRY-009 | controlflow, return, crypto | Soft-null CERTS + null-peer pin skip is the crypto binding hole; FSM + hard-fail parse + pin required together. |
| IO-006 × CRY-006 | io, crypto | `0600`/CookieAuthFile (IO) complementary to 32-byte enforce + wipe (CRY); land together. |
| IO claim “Control non-loopback cookie/hash landed” | io vs CRY-001 | Android `requireSafeControl` only; **ControlServer NULL still OPEN** in core. Do not mark CRY-001 FIXED. |
| CPU-001 × CRY-002 | cpu, crypto | Cell crypto budget OK; **never** weaken CT compares for speed. |
| MEM-005 × CRY-003/005 | memory, crypto | Unscrubbed circuit maps keep hop keys alive after logical close — wipe must run on real teardown. |
| TYP-003 × CRY-010 | type, crypto | Unify PKCS#1 digest helper **and** enforce verify; do not weaken AUTH. |
| Auth Boolean vs control NULL | RET-003, CRY-001 | Enforcing relay AUTH orthogonal to control NULL; do not weaken either for convenience. |

---

## Verification statement

Re-audited current main sources (no production `.kt` edits). Prior control `constantTimeEquals` claim confirmed at `ControlServer.kt:316,329` and `ControlS2k.kt:55`. Wire handshake compares and OR CERTS/AUTH binding remain open; CRY-009/CRY-010 are new High findings from this pass.
