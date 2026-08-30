package org.kotlintor.demo

/**
 * Shared honesty / inventory copy for demo shells.
 *
 * Keep in sync with `docs/CTOR_MISSING_INVENTORY.md` global counts after rescan.
 * Demos are not a completeness claim — inventory grades are.
 */
object DemoEngineStatus {
    const val VERSION: String = "0.1.0-SNAPSHOT"

    /** Short banner for Overview panels. */
    const val BANNER: String =
        "$VERSION — not audited. Feature demos only; not full C Tor parity."

    /**
     * L1 product-module snapshot (post trunnel elevation).
     * Global inventory still has many L2–L4 D2 rows.
     */
    const val L1_SNAPSHOT: String =
        "L1 inventory: D3≈213 · D2=0 · N/A≈166 (product modules). " +
            "Global still majority D2 across L2–L4."

    const val HONESTY_NOTE: String =
        "$BANNER $L1_SNAPSHOT See docs/CTOR_MASTER_INVENTORY.md."
}
