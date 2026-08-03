package org.kotlintor.hs

/**
 * OnionBalance-lite: merge introduction points from multiple backend descriptors
 * into one frontend descriptor build input (load-balance / HA onions).
 *
 * Full OnionBalance (descriptor signing with frontend key, hash ring, etc.)
 * remains a larger control-plane; this covers the intro-point aggregation step.
 */
object OnionBalance {
    data class Backend(
        val name: String,
        val introPoints: List<IntroPointDescriptor>,
    )

    /**
     * Round-robin merge of intro points, deduped by auth public key,
     * capped at [maxIntros] (Tor HS typically publishes ≤20).
     */
    fun mergeIntroPoints(
        backends: List<Backend>,
        maxIntros: Int = 10,
    ): List<IntroPointDescriptor> {
        if (backends.isEmpty()) return emptyList()
        val seen = HashSet<String>()
        val out = ArrayList<IntroPointDescriptor>(maxIntros)
        var i = 0
        var progressed: Boolean
        do {
            progressed = false
            for (b in backends) {
                if (out.size >= maxIntros) break
                if (i < b.introPoints.size) {
                    val ip = b.introPoints[i]
                    val id = ip.authPublic.joinToString("") { "%02x".format(it) }
                    if (seen.add(id)) {
                        out += ip
                        progressed = true
                    }
                }
            }
            i++
        } while (progressed && out.size < maxIntros)
        return out
    }

    fun buildInput(
        frontend: HsDescriptorBuildInput,
        backends: List<Backend>,
        maxIntros: Int = 10,
    ): HsDescriptorBuildInput =
        frontend.copy(introPoints = mergeIntroPoints(backends, maxIntros))
}
