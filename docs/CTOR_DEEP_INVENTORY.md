# Deep C Tor inventory → kotlin-tor (selective notes)

**Superseded for full enumeration by:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md)

This file keeps **hand notes** on a few subsystems. Depth grades and complete `.c`/type/op/option rows are in the generated CSV. Do **not** use this file for grading or elevate steps.

**Tree:** `/home/user/repos/tor` · **kotlin-tor:** ~197 main `.kt` · Status **0.1.0-SNAPSHOT**

## Scanner snapshot (honesty)

- **D0=0 · D1≈76 · majority D2 (~2046) · D3≈11 · N/A≈203**
- Full `or_options_t` field-by-field wiring (Layer 4) still incomplete
- Dirauth live multi-authority + keypin journal depth still thin
- Full KIST (`scheduler_kist.c`) and full WTF-PAD machines — **not ported**
- Native Tor UDP cells (spec gap)
- `lib/*` → N/A (Kotlin/JDK) by policy

Update master inventory via `python3 scripts/ctor_inventory_scan.py`, not by editing this file alone.

## Cross-platform native ops (`org.kotlintor.os.PlatformNatives`)

| OS | C Tor / docs analogue | kotlin-tor |
|----|----------------------|------------|
| Linux | sandbox/seccomp, SO_ORIGINAL_DST, TCP_INFO KIST | `LinuxSandbox`, `SeccompBpf`, `LinuxOriginalDst`, `KistMath` |
| Android | Orbot / VpnService.protect | `:android` `KotlinTorVpnService.protect` |
| macOS | launchd | `launchdPlistHint`; KIST→Lite |
| Windows | WinService | WinSW hooks |

## Directory authority / circpad / KIST

See CSV rows under `feature/dirauth`, `circuitpadding*`, `scheduler*`. Prefer CSV `depth` over any historical hand grades.
