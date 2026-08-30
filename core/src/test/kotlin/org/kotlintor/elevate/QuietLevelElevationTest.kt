package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.kotlintor.config.LogLevel
import org.kotlintor.config.QuietLevel
import org.kotlintor.config.addDefaultLogForQuietLevel

/**
 * Elevates `L1:app/config/quiet_level.c` toward D3.
 *
 * Evidence: QuietLevel + addDefaultLogForQuietLevel match quiet_level.h/c.
 */
class QuietLevelElevationTest {
    @Test
    fun `quiet_level enum wire values`() {
        assertEquals(0, QuietLevel.NONE.wire)
        assertEquals(1, QuietLevel.HUSH.wire)
        assertEquals(2, QuietLevel.SILENT.wire)
        assertEquals(QuietLevel.HUSH, QuietLevel.fromWire(1))
        assertEquals(QuietLevel.SILENT, QuietLevel.fromFlag("--quiet"))
        assertEquals(QuietLevel.HUSH, QuietLevel.fromFlag("hush"))
        assertNull(QuietLevel.fromFlag("verbose"))
    }

    @Test
    fun `add_default_log_for_quiet_level`() {
        assertEquals(LogLevel.NOTICE, addDefaultLogForQuietLevel(QuietLevel.NONE))
        assertEquals(LogLevel.WARN, addDefaultLogForQuietLevel(QuietLevel.HUSH))
        assertNull(addDefaultLogForQuietLevel(QuietLevel.SILENT))
    }
}
