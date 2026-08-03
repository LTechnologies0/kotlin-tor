# kotlin-tor

Pure **Kotlin** Tor engine: a third implementation beside **C Tor / libtor** and **Arti**.
Wire-compatible with the live Tor network, with a **C Tor–shaped surface** (torrc subset,
control-spec subset, SOCKS5H).

> **Status:** early (0.1.0-SNAPSHOT). Not anonymity-safe for production yet. Fail-closed by design.
> Do not claim Tor Browser fingerprinting. Prefer C Tor or Arti for sensitive use until audited.
>
> **Completeness:** feature demos ≠ C Tor parity. See
> [`docs/CTOR_MASTER_INVENTORY.md`](docs/CTOR_MASTER_INVENTORY.md) (D0–D4 grades) and
> [`docs/CTOR_MISSING_INVENTORY.md`](docs/CTOR_MISSING_INVENTORY.md) (elevate queue).
> Regenerate: `python3 scripts/ctor_inventory_scan.py`.
>
> **Live status:** directory bootstrap, 3-hop CREATE2/ntor/EXTEND2 (incl. CGO path), exit streams,
> SOCKS5H, and HS v3 client/host hot paths work against the public network. Scanner snapshot:
> **D0=0 · D1≈0 · majority D2 · ~11 D3** — not full C Tor parity.

## Engine identity

| Name | This project |
|------|----------------|
| Tor (network) | Speaks tor-spec / dir-spec / path-spec / rend-spec-v3 |
| C Tor / libtor | **Not** embedded; no `libtor.so` |
| Arti | **Not** embedded; no Arti JNI |
| kotlin-tor | Pure JVM Kotlin + Android AAR |

## Modules

| Module | Role |
|--------|------|
| `:core` | Crypto, cells, link, directory, circuits, HS, relay, PT manager, `TorClient` / `TorDaemon` |
| `:control` | control-spec server (cookie auth, GETINFO, SETEVENTS, SIGNAL, ADD_ONION) |
| `:proxy` | SOCKS5(H) (+ DNSPort placeholder) |
| `:cli` | `kotlin-tor` daemon / bootstrap CLI |
| `:android` | Embeddable AAR (`KotlinTorEngine`) for OnionVPN |
| `:integration-tests` | Live-network tests (opt-in) |

## Requirements

- JDK 21
- Android SDK 37 (for `:android`)
- Network access for consensus fetch / circuits

## Build

```bash
export JAVA_HOME=…   # JDK 21
./gradlew check
./gradlew :cli:installDist
```

Live bootstrap test:

```bash
./gradlew :integration-tests:test -Pkotlin.tor.liveNetwork=true
```

## Run (CLI)

```bash
./gradlew :cli:run --args='bootstrap --data ./data'
./gradlew :cli:run --args='daemon --data ./data'
```

Example torrc:

```
DataDirectory ./data
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
ControlPort 127.0.0.1:9051
CookieAuthentication 1
ClientOnly 1
```

## Android

```kotlin
val engine = KotlinTorEngine(context)
engine.start(
  onReady = { /* engine.socksPort, engine.controlPort */ },
  onError = { /* log */ },
)
```

OnionVPN integration: add engine id `KOTLIN_TOR` beside C Tor / Arti (separate app PR).

## Specs

- https://spec.torproject.org/
- Pluggable transports: managed external binaries only (`pt-spec`)

## Threat model (honest)

Multi-hop TCP overlay. Residual risks include both-ends correlation, exit observation of
cleartext HTTP, circuit sharing across identities, and implementation bugs. No silent clearnet
fallback. Localhost-only listeners by default. SafeLogging preferred.
