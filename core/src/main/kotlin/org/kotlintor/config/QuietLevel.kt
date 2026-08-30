package org.kotlintor.config

/**
 * Default startup log behavior (C Tor `quiet_level.c` / `quiet_level.h`).
 *
 * Inventory: `L1:app/config/quiet_level.c`
 *
 * When no logs are configured yet:
 * - [NONE] → NOTICE (and higher)
 * - [HUSH] (`--hush`) → WARN and higher
 * - [SILENT] (`--quiet`) → no default log
 */
enum class QuietLevel(val wire: Int) {
    NONE(0),
    HUSH(1),
    SILENT(2),
    ;

    companion object {
        @Volatile
        var current: QuietLevel = NONE

        fun fromWire(v: Int): QuietLevel = entries.firstOrNull { it.wire == v } ?: NONE

        fun fromFlag(name: String): QuietLevel? = when (name.lowercase()) {
            "quiet", "--quiet" -> SILENT
            "hush", "--hush" -> HUSH
            else -> null
        }
    }
}

/**
 * C Tor `add_default_log_for_quiet_level` — choose the default [LogLevel]
 * (or null = install nothing) for the given quiet mode.
 */
fun addDefaultLogForQuietLevel(quiet: QuietLevel = QuietLevel.current): LogLevel? =
    when (quiet) {
        QuietLevel.SILENT -> null
        QuietLevel.HUSH -> LogLevel.WARN
        QuietLevel.NONE -> LogLevel.NOTICE
    }
