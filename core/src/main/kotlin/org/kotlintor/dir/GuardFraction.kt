package org.kotlintor.dir

/**
 * Guard fraction file parser (C Tor `guardfraction.c`).
 *
 * Inventory: `L1:feature/dirauth/guardfraction.c`
 *
 * Format:
 * ```
 * guardfraction-file-version 1
 * written-at YYYY-MM-DD HH:MM:SS
 * n-inputs <consensuses> <days>
 * guard-seen <fpr40> <pct0-100> <appearances>
 * ```
 */
object GuardFraction {
    data class Entry(
        val identityHex: String,
        val percentage: Int,
        val appearances: Int,
    )

    data class File(
        val version: Int,
        val writtenAt: String?,
        val nConsensuses: Int,
        val nDays: Int,
        val guards: List<Entry>,
    )

    fun parse(text: String): File {
        var version = 0
        var writtenAt: String? = null
        var nCons = 0
        var nDays = 0
        val guards = ArrayList<Entry>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val sp = line.split(Regex("\\s+"))
            when (sp[0]) {
                "guardfraction-file-version" ->
                    version = sp.getOrNull(1)?.toIntOrNull() ?: error("bad version")
                "written-at" ->
                    writtenAt = sp.drop(1).joinToString(" ")
                "n-inputs" -> {
                    nCons = sp.getOrNull(1)?.toIntOrNull() ?: 0
                    nDays = sp.getOrNull(2)?.toIntOrNull() ?: 0
                }
                "guard-seen" -> {
                    require(sp.size >= 4) { "bad guard-seen line" }
                    val fp = sp[1].lowercase()
                    require(fp.length == 40 && fp.all { it in "0123456789abcdef" }) {
                        "bad digest $fp"
                    }
                    val pct = sp[2].toInt()
                    require(pct in 0..100) { "pct out of range" }
                    guards += Entry(fp, pct, sp[3].toInt())
                }
            }
        }
        require(version == 1) { "unsupported guardfraction version $version" }
        return File(version, writtenAt, nCons, nDays, guards)
    }

    /**
     * Apply percentages onto [votePercentages] for known identities.
     * When [onlyKnown] is true, skip digests not already present in the map.
     */
    fun applyTo(
        votePercentages: MutableMap<String, Int>,
        file: File,
        onlyKnown: Boolean = false,
    ): Int {
        var n = 0
        for (g in file.guards) {
            if (onlyKnown && !votePercentages.containsKey(g.identityHex)) continue
            votePercentages[g.identityHex] = g.percentage
            n++
        }
        return n
    }

    /** C Tor `dirserv_read_guardfraction_file_from_str`. */
    fun dirservReadGuardfractionFileFromStr(
        text: String,
        votePercentages: MutableMap<String, Int> = LinkedHashMap(),
    ): Int {
        val file = parse(text)
        return applyTo(votePercentages, file)
    }

    /** C Tor `dirserv_read_guardfraction_file` — same as from-str when given file contents. */
    fun dirservReadGuardfractionFile(
        text: String,
        votePercentages: MutableMap<String, Int> = LinkedHashMap(),
    ): Int = dirservReadGuardfractionFileFromStr(text, votePercentages)
}

