# C Tor → kotlin-tor source map

**Superseded for completeness grading by:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md)  
(CSV: [`generated/ctor_master_inventory.csv`](generated/ctor_master_inventory.csv) · queue: [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md))

**C Tor tree:** `/home/user/repos/tor`  
**Scale:** ~383 product `.c` (ex test/ext) vs kotlin-tor ~197 main Kotlin sources.

Honesty: a line-by-line 1:1 of all types/APIs/control-flows is multi-year. This map is a **directory correspondence** cheat-sheet only — no depth grading here.

## Directory correspondence

| C Tor | kotlin-tor | Note |
|-------|------------|------|
| `src/core/or/` | `circuit/`, `link/`, `cell/` | See CSV for depth |
| `src/core/crypto/` | `crypto/`, `circuit/Cgo*` | ntor/CGO hot paths D3; rest audit |
| `src/core/proto/` | `cell/`, `link/`, `net/` | Partial |
| `src/feature/client/` | `TorClient`, `proxy/`, `path/` | Live client |
| `src/feature/control/` | `:control` | ControlServer covers many `.c` |
| `src/feature/hs/` + `hs_common/` | `hs/`, `pow/` | hs_client/service/replaycache D3 |
| `src/feature/relay/` | `relay/` | Partial — not full relay |
| `src/feature/dirauth/` | `dir/` | Quorum harness; keypin/dirvote thinner |
| `src/app/config/` | `config/TorConfig` + manpage keys | Layer-4 options matrix |
| `src/lib/*` | JDK/Kotlin/BC | Mostly N/A equivalents |
| `src/feature/rend/` | — | N/A legacy HS v2 |

Elevate via [`PARITY_PROCESS.md`](PARITY_PROCESS.md). Do **not** vendor `libtor.so`.
