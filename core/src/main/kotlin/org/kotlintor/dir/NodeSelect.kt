package org.kotlintor.dir

/**
 * Node selection helpers (C Tor `node_select.c` / weight by bandwidth).

 * Inventory: `L1:feature/nodelist/node_select.c`
 */
object NodeSelect {
    fun byBandwidth(relays: List<RouterStatus>, preferFlags: Set<String> = emptySet()): RouterStatus? {
        val pool = relays.filter { it.isRunning && it.isFast }
            .filter { r -> preferFlags.isEmpty() || preferFlags.any { it in r.flags } }
        if (pool.isEmpty()) return null
        val weights = pool.map { (it.bandwidth.coerceAtLeast(1)).toDouble() }
        val total = weights.sum()
        var r = org.kotlintor.util.SecureRandomSource.nextDouble() * total
        for (i in pool.indices) {
            r -= weights[i]
            if (r <= 0) return pool[i]
        }
        return pool.last()
    }

    fun pickDistinct(
        relays: List<RouterStatus>,
        n: Int,
        exclude: Set<String> = emptySet(),
        preferFlags: Set<String> = emptySet(),
    ): List<RouterStatus> {
        val out = ArrayList<RouterStatus>(n)
        val used = exclude.map { it.uppercase() }.toMutableSet()
        repeat(n) {
            val cand = relays.filter { it.fingerprintHex !in used }
            val pick = byBandwidth(cand, preferFlags) ?: return out
            out += pick
            used += pick.fingerprintHex
        }
        return out
    }

    /** C Tor `choose_array_element_by_weight`. */
    fun chooseArrayElementByWeight(elements: List<String>, weights: List<Double>): String? {
        if (elements.isEmpty() || elements.size != weights.size) return null
        val total = weights.sum().coerceAtLeast(0.0)
        if (total <= 0.0) return elements.first()
        var r = org.kotlintor.util.SecureRandomSource.nextDouble() * total
        for (i in elements.indices) {
            r -= weights[i].coerceAtLeast(0.0)
            if (r <= 0) return elements[i]
        }
        return elements.last()
    }

    /** C Tor `frac_nodes_with_descriptors`. */
    fun fracNodesWithDescriptors(haveDesc: Int, total: Int): Double {
        if (total <= 0) return 0.0
        return haveDesc.coerceIn(0, total).toDouble() / total.toDouble()
    }

    /** C Tor `node_sl_choose_by_bandwidth`. */
    fun nodeSlChooseByBandwidth(relays: List<RouterStatus>): RouterStatus? =
        byBandwidth(relays)
}
