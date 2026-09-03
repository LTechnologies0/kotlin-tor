# kotlin-tor

Pure **Kotlin** Tor engine: a third implementation beside **C Tor / libtor** and **Arti**.
Wire-compatible with the live Tor network, with a **C Tor–shaped surface** (torrc subset,
control-spec subset, SOCKS5H).

> **Status:** early (**0.1.1**). Not anonymity-safe for production yet. Fail-closed by design.
> Do not claim Tor Browser fingerprinting. Prefer C Tor or Arti for sensitive use until audited.
>
> **Completeness:** feature demos ≠ C Tor parity. See
> [`docs/CTOR_MASTER_INVENTORY.md`](docs/CTOR_MASTER_INVENTORY.md) (D0–D4 grades) and
> [`docs/CTOR_MISSING_INVENTORY.md`](docs/CTOR_MISSING_INVENTORY.md) (elevate queue).
> Regenerate: `python3 scripts/ctor_inventory_scan.py`.
>
> **Live status:** directory bootstrap, 3-hop CREATE2/ntor/EXTEND2 (incl. CGO path), exit streams,
> SOCKS5H, and HS v3 client/host hot paths work against the public network. Scanner snapshot:
> **L1: D3≈213 · D2=0 · N/A≈166**; global still **majority D2** across L2–L4 — not full C Tor parity.

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
| `:demo-common` | Shared demo feature runners (`DemoSession` / `DemoFeatures`) — extras |
| `:demo-android` | Material 3 Android demo shell (+ VPN) — extras |
| `:demo-desktop` | Compose Desktop Material 3 demo shell — extras |
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

## Demo shells (extras)

Opt-in modules (omit from OnionVPN `includeBuild` by default):

```bash
./gradlew :demo-android:assembleDebug -Pkotlin.tor.extras=true
./gradlew :demo-desktop:createDistributable -Pkotlin.tor.extras=true
# Full-tunnel VPN needs CAP_NET_ADMIN — do not use sudo ./gradlew (JAVA_HOME is stripped):
sudo ./bin/kotlin-tor-demo
# or: sudo -E env "PATH=$PATH" "JAVA_HOME=$JAVA_HOME" ./bin/kotlin-tor-demo
```

Signed Android release APK (local):

```bash
scripts/android-release-keystore.sh          # once; writes gitignored JKS + keystore.properties
./gradlew :demo-android:assembleRelease -Pkotlin.tor.extras=true
```

- `:demo-common` — JVM feature runners shared by both GUIs (incl. Linux `DesktopVpnSession`)
- `:demo-android` — clean Material 3 shell; VPN / TUN via `VpnService` + OnionTunnel
- `:demo-desktop` — Compose Desktop Material 3; **Linux full-tunnel** VPN (`/dev/net/tun` + SO_MARK; needs `CAP_NET_ADMIN`)
- `:cli` — headless daemon / debug (not a GUI)

Desktop VPN excludes **only Tor OR/PT uplink** sockets from the tunnel (SO_MARK + policy routing). Not anonymity-certified; SNAPSHOT.

Packaged binary: `demo-desktop/build/compose/binaries/main/app/kotlin-tor-demo/` (launcher wrapper: [`bin/kotlin-tor-demo`](bin/kotlin-tor-demo)).

## CI / Release artifacts

| Workflow | Trigger | Output |
|----------|---------|--------|
| [`ci`](.github/workflows/ci.yml) | push / pull request | JVM checks, `:android` + `:demo-android` debug APKs, `:demo-desktop` assemble |
| [`release`](.github/workflows/release.yml) | tag `v*` or **Actions → release → Run workflow** | Windows zip (+ MSI when WiX is available), Linux AppImage/tarball, **signed** release APK |

`release` uploads Actions artifacts always. On a `v*` tag — or when **Create or update a GitHub Release** is checked — it also attaches them to the GitHub Release.

### Signed APK secrets

The Android job **fails closed** until these repository secrets exist
(**Settings → Secrets and variables → Actions**). Never commit a keystore.

| Secret | Value |
|--------|--------|
| `ANDROID_KEYSTORE_BASE64` | `base64 -w0 release.jks` (no newlines) |
| `ANDROID_KEYSTORE_PASSWORD` | JKS store password |
| `ANDROID_KEY_ALIAS` | key alias (script default: `kotlintor`) |
| `ANDROID_KEY_PASSWORD` | optional; defaults to the store password |

Local equivalent (gitignored): `keystore.properties` with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`.

## Specs

- https://spec.torproject.org/
- Pluggable transports: managed external binaries only (`pt-spec`)

## Threat model (honest)

Multi-hop TCP overlay. Residual risks include both-ends correlation, exit observation of
cleartext HTTP, circuit sharing across identities, and implementation bugs. No silent clearnet
fallback. Localhost-only listeners by default. SafeLogging preferred.
