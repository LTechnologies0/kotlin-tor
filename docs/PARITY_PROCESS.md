# Parity elevate process (anti-false-done)

**Completeness truth:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md)  
**Queue:** [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md) (generated)  
**Human backlog TODO:** [`CTOR_PARITY_TODO.md`](CTOR_PARITY_TODO.md) (all D2/N/A by family)  
**Feature board only:** [`../PARITY_GAPS.md`](../PARITY_GAPS.md)

## Rules for `/loop` and agents

1. Do **not** answer “implement every partial” with a single wake + “done.”
2. Pick the next row from the lowest-depth queue (**D1 → D2**) in priority modules. (D0 is currently empty.)
3. Every code change must cite one or more inventory `row_id` values.
4. Raise depth by **at most one grade** per change, with evidence (test name + C Tor symbol).
5. Kotlin KDoc containing `lite)` or `not ported` forces ≤ `D2` (`scripts/ctor_inventory_scan.py --check-lite`).
6. Tag releases explicitly (e.g. `v0.1.1`); post-tag development may return to `*-SNAPSHOT`.
7. Phase OM (onionmasq-class NI) is a **product surface** track — do **not** invent inventory rows or board ✅ for it.

## Naming (codefile + API)

C Tor basenames map to a **primary** Kotlin file `ExpectedPascal.kt` (see `scripts/ctor_naming.py` `STEM_PASCAL`).

1. Underscores split words: `congestion_control_flow` → `CongestionControlFlow.kt`.
2. Concatenated stems use the dictionary (`circuitlist` → `CircuitList`, not `Circuitlist`).
3. `BASENAME_HINTS` primary path **must** be that file (facades with `typealias` are OK).
4. Public APIs expose camelCase of C Tor snake_case (`tor_run_main` → `torRunMain`) alongside idiomatic names.
5. Check: `python3 scripts/ctor_naming.py --check-d3` (D3 rows must pass). Full L1: `--check` (WIP).
   Also: `ctor_inventory_scan.py --check-naming`.

## Commands

```bash
export CTOR_SRC=/home/user/repos/tor
python3 scripts/ctor_inventory_scan.py
python3 scripts/ctor_inventory_scan.py --check-lite
python3 scripts/ctor_inventory_scan.py --check-naming
./gradlew :core:test --tests 'org.kotlintor.elevate.*'
```

## After elevating

1. Re-run the scanner (updates CSV + missing queue + master summary).
2. If a unit truly reaches D3, update seed depth in `scripts/ctor_inventory_scan.py` (`SEED_DEPTH`) or improve match heuristics — do not hand-edit CSV as source of truth.
3. Only then adjust PARITY feature-board rows, and only if linked inventory rows are ≥ D3.
