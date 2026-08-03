# Domain: crypto

Scope: `core/.../crypto/` (ntor / ntor-v3 / CGO / AES-CTR / CreateFast), control auth (`:control` SAFECOOKIE / COOKIE / HASHEDPASSWORD / NULL), `util` (`constantTimeEquals`, `secureWipe`, `SecureRandomSource`). Cap ~8.

## Critical / High summary

| ID | Risk | One-liner |
|----|------|-----------|
| CRY-001 | **High** (Critical + IO-005) | Control NULL / empty-or-any password AUTHENTICATE fails open when cookie+hash unset |
| CRY-002 | **High** | Wire AUTH/MAC/KH compares use `contentEquals` (ntor, ntor-v3, hs-ntor, CreateFast) |
| CRY-003 | **High** | Ephemeral DH/seed material not wiped after handshake (NtorV3 / HsNtor / CreateFast / ClientState) |
| CRY-004 | **Medium** | CreateFast still client-callable; relay always accepts (`supportsCreateFast=true`) |
| CRY-005 | **Medium** | `secureWipe` = `fill(0)` only; AES-CTR/CGO keys have no destroy path |
| CRY-006 | **Medium** | Control cookie heap not wiped; SAFECOOKIE/COOKIE read does not enforce 32-byte length |
| CRY-007 | **Low** (mitigated) | Control COOKIE/SAFECOOKIE/S2K already use `constantTimeEquals` |
| CRY-008 | **Low** (ok) | Handshake RNG via `SecureRandomSource` / `SecureRandom()` — adequate on modern JVMs |

---

### [CRY-001] Control NULL / password AUTHENTICATE fail-open
- **Track**: crypto
- **Evidence**:
  - `control/.../ControlServer.kt:257-266` — `METHODS=NULL` when `cookieAuthentication` off and `hashedControlPassword` blank
  - `:279-284` — empty `AUTHENTICATE` → `authenticated = true`
  - `:296-299` — quoted password accepted whenever hash unset and cookie off (any string)
  - `:346-350` — hex blob path same NULL grant
  - Default config still prefers cookie (`TorConfig.kt:13` `cookieAuthentication = true`); fail-open only when operator disables both
- **Risk**: High (Critical if ControlPort non-loopback — IO-005 / FAIL-004)
- **Exploit logic**: Attacker reaches Control → `AUTHENTICATE` / `AUTHENTICATE "x"` → full `SIGNAL`/`SETCONF`/`ADD_ONION`
- **Fix**: Refuse non-loopback Control without cookie or hashed password; optionally refuse NULL entirely outside test builds. Keep SAFECOOKIE/COOKIE fail-closed paths as-is
- **Related**: FAIL-004, IO-005, IO-006

### [CRY-002] Handshake AUTH / MAC / KH use non-constant-time compare
- **Track**: crypto
- **Evidence**:
  - `crypto/Ntor.kt:64` — `expectedAuth.contentEquals(auth)`
  - `crypto/NtorV3.kt:135`, `:205` — AUTH and client MAC
  - `crypto/CreateFast.kt:34` — KH wire check
  - `hs/HsNtor.kt:136`, `:182` — hs-ntor AUTH / INTRODUCE2 MAC
  - Control path already fixed: `ControlServer.kt:316,329` + `ControlS2k.kt:55` use `constantTimeEquals`
- **Risk**: High (remote timing on circuit/HS handshakes; local control was Medium and is largely mitigated)
- **Fix**: Replace AUTH/MAC/KH secret compares with `constantTimeEquals` (same helper as control). Keep public ID/KEYID checks as-is or constant-time for uniformity
- **Related**: CRY-007 (control positive), FAIL auth

### [CRY-003] Ephemeral secrets survive handshake without wipe
- **Track**: crypto
- **Evidence**:
  - `Ntor.kt:68-70` wipes `secretXy`/`secretXb`/`secretInput` but **not** `state.secretKey`, HKDF `keys` buffer, or `Result.keySeed`
  - `NtorV3.kt:108-141` — `yx`, `bx` (also retained on `ClientState`), `secretInput`, `clientSk` never wiped
  - `HsNtor.kt:125-137`, `:174-189` — shared secrets / seed material uncleared
  - `CreateFast.kt` / `CreateOnehop.kt` — client `x` and seed material retained for GC only
  - Contrast: `NtorServer.kt:32-34` matches client wipe of DH products only
- **Risk**: High (heap dumps / swap / crash cores retain circuit/HS keying material)
- **Fix**: After successful finish (and on failure paths): wipe ephemeral sk, DH outputs, seeds, and intermediate HKDF buffers; clear `ClientState` fields; document that live hop keys in `HopCrypto`/`CgoHop` remain until circuit close (then wipe — CRY-005)
- **Related**: CRY-005, MEM hop lifetime

### [CRY-004] CreateFast still available (client + relay always-on)
- **Track**: crypto
- **Evidence**:
  - `crypto/CreateFast.kt` — SHA1 KDF-TOR; no DH (X‖Y over OR TLS)
  - `circuit/Circuit.kt:205-219` `createFirstHopFast`; `:933-937` used when `useCreateOnehop=false`
  - `relay/RelayService.kt:482-488`, `:854-867` handles `CREATE_FAST` unconditionally
  - `relay/RelayConfigFindAddr.kt:251` `supportsCreateFast(...) = true`
- **Risk**: Medium (legacy one-hop dir; weaker than ntor if OR TLS/logs compromised; relay cannot refuse)
- **Fix**: Prefer CreateOnehop/ntor for dir circuits; gate relay `CREATE_FAST` behind config/consensus (mirror C Tor); document residual use; fail closed on EXTEND carrying CreateFast
- **Related**: deferred disable; CreateOnehop prop364 also non-DH but stronger KDF

### [CRY-005] `secureWipe` + AES-CTR/CGO key destroy gaps
- **Track**: crypto
- **Evidence**:
  - `util/Bytes.kt:18-20` — `secureWipe()` only `fill(0)` (no native mlock/Cleaner; copies/`copyOfRange` untouched)
  - `crypto/AesCtr.kt:11-18` — `KeyParameter(key)` into BC SIC engine; no `destroy`/wipe of key or cipher state
  - `circuit/CircuitCrypto.kt:47-48` — hop ciphers hold keys for circuit life with no close wipe
  - `crypto/CgoHop.kt:19-33` — rotatable `keys`/`nonce` arrays; no wipe on hop teardown; recognition still `contentEquals` (`:65`, `:83`)
  - `Cgo.kt` ET/PRF copy `kb`/`ku`/`k` slices without wipe after use
- **Risk**: Medium (defense-in-depth; amplifies CRY-003)
- **Fix**: Wipe hop/CGO key arrays on circuit close; optional AesCtr.close() zeroing; treat wipe as best-effort but call it consistently; use constant-time compare for CGO nonce recognition if side channels matter
- **Related**: CRY-003

### [CRY-006] Control cookie bytes linger; length not enforced
- **Track**: crypto
- **Evidence**:
  - `TorDaemon.kt:153-155` — `SecureRandomSource.nextBytes(32)` then `Files.write`; in-memory `cookie` never `secureWipe`
  - `ControlServer.kt:245-248`, `:327-329` — `Files.readAllBytes` for SAFECOOKIE/COOKIE; no `cookie.size == ControlCookie.COOKIE_LEN` (32)
  - Truncated/overlong cookie file → weak or length-leaking compare (`constantTimeEquals` early size exit at `Bytes.kt:26`)
- **Risk**: Medium
- **Fix**: Enforce 32-byte cookie on write and read (fail closed); wipe buffers after HMAC; pair with IO-006 `0600` / CookieAuthFile
- **Related**: IO-006, CRY-001, CRY-007

### [CRY-007] Control secret compares already constant-time (positive)
- **Track**: crypto
- **Evidence**: `ControlServer.kt:316` SAFECOOKIE ClientHash; `:329` COOKIE; `ControlS2k.kt:55` HashedControlPassword; helper `util/Bytes.kt:22-31`
- **Risk**: Low (mitigated for control auth material)
- **Fix**: None for control; extend pattern to CRY-002 wire handshakes
- **Related**: CRY-002

### [CRY-008] SecureRandom usage for crypto material (ok / residual)
- **Track**: crypto
- **Evidence**:
  - Handshake/cookie/padding: `SecureRandomSource` (`Bytes.kt:72-76`) — shared `SecureRandom()`
  - `Curve25519.generateKeyPair`, `CreateFast`/`CreateOnehop` X/Y, `ControlS2k` salt, `TorDaemon` cookie, `OrAuthenticate` rand
  - TLS: `TorSsl.kt:37` / `OrCertMaterial` pass `SecureRandom()` into `SSLContext.init`
  - Non-crypto: `WebSocketFrame.kt:32` per-call `SecureRandom()` for masks only
- **Risk**: Low on Linux/Android default providers; residual if a JVM substitutes a weak `SecureRandom` SPI
- **Fix**: Optional `SecureRandom.getInstanceStrong()` (or explicit NativePRNG) for `SecureRandomSource` only; keep single process-wide instance
- **Related**: —

## Conflicts
- **CRY-001 vs FAIL-004 / IO-005**: Aligned — crypto owns auth fail-open; IO owns bind gate. Non-loopback Control requires cookie or hashed password; do not “fix” NULL for remote convenience.
- **CRY-001 vs lab/torrc NULL**: Loopback-only NULL for tests OK; product/VPN defaults keep `CookieAuthentication 1` (already default).
- **CRY-002 vs CPU micro-cost**: Always prefer constant-time for AUTH/MAC/KH; cost is negligible vs crypto.
- **CRY-003/005 vs GC / live hop keys**: Wipe ephemerals immediately after derive; live `HopCrypto`/`CgoHop` keys stay until circuit close — then wipe (order with MEM circuit teardown).
- **CRY-004 vs dir-circuit compatibility**: Disabling CreateFast on relay may break old clients; prefer config flag default-off for pure clients, default-on only when advertising legacy support.
- **CRY-006 vs IO-006 file perms**: Length/wipe (crypto) and `0600`/CookieAuthFile (io) are complementary; land together.
- **CRY-007 vs stale AUDIT_BOARD CRY-001**: Board still listed control `contentEquals` — superseded; control fixed, wire handshakes remain CRY-002.
