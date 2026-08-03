package org.kotlintor.config

/**
 * PathBias* torrc options (C Tor `circpathbias.c` / or_options_t).
 */
data class PathBiasOptions(
    val circThreshold: Int = 100,
    val noticeRate: Double = 0.70,
    val warnRate: Double = 0.50,
    val extremeRate: Double = 0.30,
    val noticeCountPercentile: Int = 95,
    val scaleThreshold: Int = 300,
    val scaleUseThreshold: Int = 100,
    val dropGuards: Boolean = false,
    val useThreshold: Int = 20,
    val noticeUseRate: Double = 0.80,
    val extremeUseRate: Double = 0.60,
    val useRate: Double = 0.60,
) {
    companion object {
        val DEFAULT = PathBiasOptions()
    }
}
