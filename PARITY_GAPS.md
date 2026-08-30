# kotlin-tor ↔ C Tor parity gap map (feature board)

Status: **0.1.1** — functional client + partial relay/HS. Not anonymity-audited.  
Goal: pure-Kotlin rewrite of C Tor (no `libtor.so` / Arti JNI). BouncyCastle OK.

## READ THIS FIRST

**This file is a feature / demo board, not completeness truth.**

| Truth artifact | Role |
|----------------|------|
| [`docs/CTOR_MASTER_INVENTORY.md`](docs/CTOR_MASTER_INVENTORY.md) | Depth taxonomy D0–D4 / N/A |
| [`docs/generated/ctor_master_inventory.csv`](docs/generated/ctor_master_inventory.csv) | Every product `.c`, type, op sample, `or_options` field |
| [`docs/CTOR_MISSING_INVENTORY.md`](docs/CTOR_MISSING_INVENTORY.md) | Generated lowest-depth elevate queue |

**Inventory snapshot** (regenerate with `python3 scripts/ctor_inventory_scan.py`):

- ~379 Layer-1 `.c` rows · ~126 types · ~1600 ops · ~227 options
- Depth reality: **D0=0**, **D1≈0**, **D2≈1043**, **D3≈1090**, **N/A≈203** — not “almost done”
- Human checklist of every open unit: [`docs/CTOR_PARITY_TODO.md`](docs/CTOR_PARITY_TODO.md)
- Dozens of Kotlin files self-label `lite`; full KIST + full WTF-PAD machines are **not ported**

**Rule:** A row below may be ✅ only if linked master-inventory units are ≥ `D3`.  
`lite` / `not ported` KDoc ⇒ at most 🟡. Elevations must cite `row_id`.

Legend: ✅ ≥D3 hot-path · 🟡 D1–D2 partial · ❌ D0 missing · 🚫 out of scope / deprecated

---

## A. Link / channel (tor-spec)

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| TLS OR connection | 🟡 | Live TLS path; `L1:…/channeltls.c` / `connection_or` still D2 (lite-capped) |
| VERSIONS / NETINFO / PADDING | 🟡 | Works on live OR; full `versions.c` / pad edge cases thinner |
| CERTS RSA 1–2 | 🟡 | Live on OR path; no standalone ≥D3 inventory unit |
| CERTS Ed25519 4–5 | 🟡 | Live on OR path; no standalone ≥D3 inventory unit |
| CERTS type 7 RSA↔Ed CrossCert | 🟡 | Live on OR path; no standalone ≥D3 inventory unit |
| AUTHENTICATE / AUTH_CHALLENGE | 🟡 | Conscrypt exporters work; control-flow vs full `connection_or` auth still D2-ish |
| Channel padding (prop254) | 🟡 | Cell + controller; not full `channelpadding.c` |
| Circuit padding machines (prop302) | 🟡 | `L1:circuitpadding*.c` D2 — wtfPadLite; live middle ACK missing |
| CREATE_FAST | 🟡 | `L1:onion_fast.c` D2 — not proven D3 |
| CREATE2 ntor / ntor-v3 | ✅ | `L1:onion_ntor*.c` D3 |
| CreateOnehop (prop364) | 🟡 | Implemented path; not full C surface |

## B. Circuit crypto

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| tor1 AES-CTR + SHA1 hop | 🟡 | Live hop crypto; `relay_crypto*` still D2 |
| HS virtual AES-256 + SHA3 | 🟡 | Live HS path; `hs_ntor.c` still D2 |
| Classic SENDME v1 | 🟡 | Works with CC; full `sendme.c` unaudited |
| Prop324 Vegas CongestionControl | 🟡 | Wired subset; `congestion_control_*.c` mostly D2 |
| CC_FIELD_REQUEST on wire | 🟡 | |
| CGO Prop359 | ✅ | `L1:relay_crypto_cgo.c` D3 — vectors + live EXTEND V1 |
| Conflux (prop329) | 🟡 | Codecs/scheduler lite vs full `conflux_*.c` |
| Stream-level SENDME | 🚫 | Deprecated under FlowCtrl=2 / CC |

## C. Directory

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| Authority bootstrap / microdesc consensus | 🟡 | Client fetch works; many `dirparse`/`nodelist` units D0–D2 |
| Microdesc fetch + parse | 🟡 | |
| Dir cache BEGIN_DIR serve | 🟡 | |
| Full DirPort HTTP | 🟡 | Listener exists; not full `dircache`/`dirserv` |
| Descriptor publish (relay) | 🟡 | |
| Bandwidth measurement / votes | 🟡 | Lite collator / bwauth |
| Directory authority | 🟡 | Quorum harness ≠ production `dirvote`/`keypin` depth |
| Consensus diffs / routerset / dlstatus | 🟡 | Lite mirrors |
| Circuitmux / half-edge / pathbias / CBT | 🟡 | `circuitmux*.c` D2; DropGuards thinner |
| Onion queue / hibernate / rephist | 🟡 | Explicit lite |

## D. Path / guards

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| 3-hop path select | 🟡 | Works live; `node_select`/`nodelist` not D3 |
| Sticky entry guards | 🟡 | `entrynodes` / `EntryGuardFsm` lite |
| Vanguards / HS path restrictions | 🟡 | |
| ExcludeNodes / Family | 🟡 | |
| Circuit dirty / unused timeouts | 🟡 | |

## E. Streams / proxies

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| RELAY BEGIN/DATA/END/CONNECTED | 🟡 | Live SOCKS works; `connection_edge` lite |
| SOCKS5H | 🟡 | Production path OK; not full `proto_socks`/`dnsserv` |
| HTTP CONNECT | 🟡 | |
| Isolation flags | 🟡 | |
| DNSPort / Transparent | 🟡 | |
| Optimistic data | 🟡 | |

## E2. Pure-Kotlin net / proxy control plane

These are **kotlin-tor additions** (RFC codecs / frontends), not C Tor module parity.  
Status here means “implemented in-repo,” not “exists in C Tor.”

| Item | Status | Notes |
|------|--------|-------|
| BytePipe + StreamShaper + codecs (SOCKS/HTTP/FTP/…) | ✅ | `org.kotlintor.net` |
| Bilingual / TransPort / DNSPort / FTP / FixedTorTunnel | ✅ | ConnectionTable listeners |
| Tor UDP exit / cell UDP | 🟡 | Gateway + ExitUdp; cell-level Tor UDP ❌ (spec) |
| TUN ↔ Tor / VpnService | 🟡 | Works for Android hook; not C Tor |

## F. Control port (control-spec)

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| SAFECOOKIE / HashedControlPassword | 🟡 | Works; `control_auth.c` mapped D2 (single ControlServer) |
| GETINFO / CIRC events subset | 🟡 | |
| ADD_ONION / DEL_ONION | 🟡 | |
| SETCONF / SAVECONF / RESETCONF | 🟡 | |
| HSFETCH / HSPOST | 🟡 | |
| Full event set | 🟡 | Names present ≠ full `control_events.c` / btrack_* |
| OwningControllerProcess | 🟡 | |

## G. Onion services v3

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| Address / blinding / desc decrypt | 🟡 | Strong crypto path; many `hs_*.c` still D1/D2 |
| Client INTRODUCE/RENDEZVOUS/BEGIN | ✅ | `L1:hs_client.c` D3 |
| Host ESTABLISH_INTRO + publish | ✅ | `L1:hs_service.c` D3 (edge gaps noted) |
| Intro re-establish / virtport | 🟡 | |
| INTRODUCE2 replay cache | ✅ | `L1:replaycache.c` D3 |
| PoW (prop327) | 🟡 | Equi-X vectors; full `hs_pow.c` surface thinner |
| OnionBalance / rate limits | 🟡 | Frontend lite; no OB hash-ring IPC |
| Client auth (x25519) | 🟡 | |

## H. Relay / bridge

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| ORPort TLS + CREATE2 + EXTEND2 | 🟡 | Large `RelayService`; many `feature/relay/*.c` still D1/D2 — not “done relay” |
| BEGIN_DIR cache | 🟡 | |
| Exit BEGIN + ExitPolicy | 🟡 | |
| Descriptor publish / DirAuth POST | 🟡 | |
| DirPort listener | 🟡 | |
| Bridge + ExtORPort PT | 🟡 | ExtOR `L1:ext_orport.c` D3; PT manager partial |
| MetricsPort / heartbeat | 🟡 | `status.c` → HeartbeatStatus D1 |
| DoS subsystem | 🟡 | Lite / config knobs |
| Onion key rotation | 🟡 | |

## I. Circumvention

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| UseBridges + Bridge lines | 🟡 | |
| Client/Server PT launch | 🟡 | External binaries; not full `transports.c` |
| BridgeDB / Moat | 🟡 | |

## J. Config / process

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| torrc subset (typed hot keys) | 🟡 | |
| Full torrc(5) / `or_options_t` | 🟡 | Layer-4: remaining D1 ack-only + majority D2; **not** full semantic wiring |
| Sandbox / seccomp | 🟡 | Linux subset; not full `lib/sandbox` |
| systemd / WinService / launchd | 🟡 | Packaging hooks |
| Cross-platform natives | 🟡 | TCP_INFO / protect partial |
| `--keygen` OfflineMasterKey | 🟡 | |

## K. Android

| Item | Status | Notes / inventory |
|------|--------|-------------------|
| AAR lifecycle API | 🟡 | |
| VpnService / OnionVPN hook | 🟡 | |
| Orbot-compatible control | 🟡 | |

---

## Implementation priority

Follow **[`docs/CTOR_MISSING_INVENTORY.md`](docs/CTOR_MISSING_INVENTORY.md)** (generated D1→D2 queue).  
Cite `row_id` on every elevate. Raise at most one depth grade with evidence.

```bash
python3 scripts/ctor_inventory_scan.py
python3 scripts/ctor_inventory_scan.py --check-lite
```

**Parity board honesty:** Still **0.1.0-SNAPSHOT**. Master inventory: **D0=0 · D1≈76 · majority D2 · ~11 D3** — do not claim C Tor parity from this feature board.
