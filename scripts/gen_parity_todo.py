#!/usr/bin/env python3
"""Generate docs/CTOR_PARITY_TODO.md from ctor_master_inventory.csv."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "docs" / "generated" / "ctor_master_inventory.csv"
OUT = ROOT / "docs" / "CTOR_PARITY_TODO.md"

PREFIXES = [
    "pathbias_",
    "btrack_",
    "bto_",
    "control_event_",
    "control_reply_",
    "control_",
    "connection_control_",
    "hs_",
    "nodelist_",
    "router_",
    "dirvote_",
    "dirauth_",
    "relay_",
    "circuit_",
    "edge_",
    "connection_",
    "proxy_",
    "getinfo_helper_",
    "handle_control_",
    "sr_state_",
    "dirserv_",
    "microdesc_",
    "networkstatus_",
    "node_get_",
    "routerset_",
    "authority_cert_",
    "tor_cert_",
    "or_handshake_",
    "options_act_",
    "options_validate_",
    "dns_",
    "keypin_",
]


def family(unit: str) -> str:
    u = unit.rstrip("_")
    for p in PREFIXES:
        if u.startswith(p):
            return p.rstrip("_")
    parts = u.split("_")
    return "_".join(parts[:2]) if len(parts) >= 2 else parts[0]


def main() -> None:
    rows = list(csv.DictReader(CSV.open()))
    d2 = [r for r in rows if r["depth"] == "D2"]
    na = [r for r in rows if r["depth"] == "N/A"]
    d3 = [r for r in rows if r["depth"] == "D3"]
    l3 = [r for r in d2 if r["row_id"].startswith("L3")]
    l4 = [r for r in d2 if r["row_id"].startswith("L4")]

    lines: list[str] = []
    lines += [
        "# kotlin-tor ↔ C Tor parity TODO (generated backlog)",
        "",
        f"_Generated {date.today().isoformat()} from `docs/generated/ctor_master_inventory.csv`._",
        "",
        "**Not a claim of completeness.** Elevate D2→D3 one grade at a time per `docs/PARITY_PROCESS.md`.",
        "Source queue: [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md). Re-run:",
        "",
        "```bash",
        "export CTOR_SRC=/path/to/tor",
        "python3 scripts/ctor_inventory_scan.py",
        "python3 scripts/gen_parity_todo.py",
        "```",
        "",
        "## Snapshot",
        "",
        "| Depth | Count |",
        "|-------|------:|",
        f"| D3 | {len(d3)} |",
        f"| **D2 (open elevate)** | **{len(d2)}** |",
        f"| N/A (platform/stub/OOS) | {len(na)} |",
        "",
        f"D2 breakdown: **{len(l3)} L3 ops** + **{len(l4)} L4 options**. "
        "L1 modules and L2 product types are already ≥D3 (or N/A).",
        "",
        "## How to use this TODO",
        "",
        "1. Work **priority modules** in order: `feature/control` → `feature/nodelist` → "
        "`feature/hs` → `feature/relay` → `feature/dirauth` → `app/config` (L4).",
        "2. Each batch ≤25 ops: camelCase aliases + `OP_SEED_DEPTH` + elevation test + rescan.",
        "3. Do **not** mark PARITY_GAPS ✅ until linked inventory rows are D3.",
        "",
        f"## A. L3 operations still D2 ({len(l3)})",
        "",
    ]

    mod_order = [
        "feature/client",
        "feature/control",
        "feature/nodelist",
        "feature/hs",
        "feature/relay",
        "feature/dirauth",
    ]
    other = sorted(set(r["ctor_module"] for r in l3) - set(mod_order))
    for mod in mod_order + other:
        items = [r for r in l3 if r["ctor_module"] == mod]
        if not items:
            continue
        fams: dict[str, list[str]] = defaultdict(list)
        for r in items:
            fams[family(r["ctor_unit"])].append(r["ctor_unit"])
        lines += [
            f"### `{mod}` — {len(items)} ops",
            "",
            "| Family / batch | Count | Example units | Kotlin primary |",
            "|----------------|------:|---------------|----------------|",
        ]
        for fam, units in sorted(fams.items(), key=lambda x: -len(x[1])):
            first = next(r for r in items if r["ctor_unit"] == units[0])
            ktor = (first["ktor_path"] or "").split(";")[0]
            for prefix in (
                "core/src/main/kotlin/org/kotlintor/",
                "control/src/main/kotlin/org/kotlintor/",
                "proxy/src/main/kotlin/org/kotlintor/",
            ):
                ktor = ktor.replace(prefix, "")
            if len(ktor) > 48:
                ktor = ktor[:45] + "..."
            ex = ", ".join(f"`{u}`" for u in units[:4])
            if len(units) > 4:
                ex += f", … (+{len(units) - 4})"
            lines.append(f"| `{fam}_*` | {len(units)} | {ex} | `{ktor}` |")
        lines.append("")

    for mod, title in [
        ("feature/control", "Control"),
        ("feature/hs", "HS"),
        ("feature/nodelist", "Nodelist"),
        ("feature/dirauth", "Dirauth"),
        ("feature/relay", "Relay"),
        ("feature/client", "Client"),
    ]:
        items = [r for r in l3 if r["ctor_module"] == mod]
        if not items:
            continue
        lines += [f"#### {title} op checklist (all {len(items)})", ""]
        fams_r: dict[str, list[dict]] = defaultdict(list)
        for r in items:
            fams_r[family(r["ctor_unit"])].append(r)
        for fam in sorted(fams_r.keys(), key=lambda f: -len(fams_r[f])):
            lines.append(f"<details><summary><code>{fam}_*</code> ({len(fams_r[fam])})</summary>")
            lines.append("")
            for r in sorted(fams_r[fam], key=lambda x: x["ctor_unit"]):
                lines.append(f"- [ ] `{r['row_id']}`")
            lines += ["", "</details>", ""]

    lines += [
        f"## B. L4 `or_options` fields still D2 ({len(l4)})",
        "",
        "Typed parse/wiring incomplete vs C Tor `or_options_t`. Module: `app/config`.",
        "",
        f"<details><summary>All {len(l4)} option names</summary>",
        "",
    ]
    for r in sorted(l4, key=lambda x: x["ctor_unit"]):
        lines.append(f"- [ ] `{r['row_id']}` — `{r['ctor_unit']}`")
    lines += ["", "</details>", ""]

    na_l1 = [r for r in na if r["row_id"].startswith("L1")]
    na_l2 = [r for r in na if r["row_id"].startswith("L2")]
    na_l4 = [r for r in na if r["row_id"].startswith("L4")]
    notes = {
        "lib/crypt_ops": "JVM/BC crypto — keep N/A unless API shim needed",
        "lib/tls": "JDK TLS / Conscrypt — keep N/A",
        "lib/compress": "JDK zip / optional codecs",
        "lib/evloop": "Kotlin coroutines / NIO",
        "lib/pubsub": "Optional event bus — decide",
        "lib/dispatch": "Optional — decide",
        "feature/rend": "Deprecated v2 onion — OOS",
        "core/or": "trace probes — OOS",
    }
    lines += [
        f"## C. N/A surface ({len(na)}) — map, stub, or out-of-scope",
        "",
        "Not “missing product features” by default: C platform libs, stubs, deprecated rend.",
        "",
        f"### C.1 N/A modules (L1) — {len(na_l1)}",
        "",
        "| Module | Count | Notes |",
        "|--------|------:|-------|",
    ]
    for m, c in Counter(r["ctor_module"] for r in na_l1).most_common():
        lines.append(f"| `{m}` | {c} | {notes.get(m, 'platform / decide')} |")
    lines += ["", "<details><summary>Full L1 N/A unit list</summary>", ""]
    for r in sorted(na_l1, key=lambda x: (x["ctor_module"], x["ctor_unit"])):
        lines.append(f"- [ ] `{r['row_id']}` — `{r['ctor_module']}/{r['ctor_unit']}`")
    lines += ["", "</details>", "", f"### C.2 N/A data types (L2) — {len(na_l2)}", ""]
    for r in sorted(na_l2, key=lambda x: x["ctor_unit"]):
        lines.append(f"- [ ] `{r['row_id']}` — `{r['ctor_unit']}` ({r['ctor_module']})")
    lines.append("")
    if na_l4:
        lines += [f"### C.3 N/A options (L4) — {len(na_l4)}", ""]
        for r in sorted(na_l4, key=lambda x: x["ctor_unit"]):
            lines.append(f"- [ ] `{r['row_id']}` — `{r['ctor_unit']}`")
        lines.append("")

    lines += [
        "## D. Feature-board gaps (product semantics — still 🟡)",
        "",
        "From [`PARITY_GAPS.md`](../PARITY_GAPS.md) — not inventory-complete until linked rows ≥D3:",
        "",
        "- [ ] TLS OR / CERTS / AUTHENTICATE full channel state machine",
        "- [ ] Channel padding + circuit padding (WTF-PAD) full machines",
        "- [ ] tor1 relay crypto audit depth; SENDME v1 + Prop324 CC wiring",
        "- [ ] Conflux full scheduler vs lite",
        "- [ ] Dir cache / DirPort / bwauth / dirvote production depth",
        "- [ ] Guards FSM / vanguards / pathbias DropGuards live path",
        "- [ ] HS client+service full descriptor/intro/rendezvous",
        "- [ ] Control protocol events + bootstrap tracking (btrack)",
        "- [ ] PT managed-proxy lifecycle beyond aliases",
        "- [ ] Relay DNS / keys / descriptor publish",
        "",
        "## E. Suggested elevate order (next batches)",
        "",
        "| # | Batch | Module | ~ops |",
        "|---|-------|--------|-----:|",
        "| 1 | btrack_* / bto_* | `feature/control` | 13 |",
        "| 2 | control_event_* | `feature/control` | 21 |",
        "| 3 | control_reply_* + control_cmd_* | `feature/control` | 25 |",
        "| 4 | getinfo_helper_* + handle_control_* | `feature/control` | 18 |",
        "| 5 | remaining control_* | `feature/control` | ~32 |",
        "| 6 | node_get_* / router_* | `feature/nodelist` | 25 |",
        "| 7 | networkstatus_* / microdesc_* | `feature/nodelist` | 25 |",
        "| 8 | hs_* client/service/descriptor | `feature/hs` | 25 |",
        "| 9 | relay dns_* / options / keys | `feature/relay` | 25 |",
        "| 10 | dirvote_* / sr_state_* / keypin_* | `feature/dirauth` | 25 |",
        "",
        "Then remaining families + L4 option wiring.",
        "",
    ]
    OUT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes); D2={len(d2)} D3={len(d3)} N/A={len(na)}")


if __name__ == "__main__":
    main()
