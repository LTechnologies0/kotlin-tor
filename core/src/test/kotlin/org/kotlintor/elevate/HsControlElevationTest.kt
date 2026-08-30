package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.hs.HsControl

/**
 * Elevates `L1:feature/hs/hs_control.c` toward D3.
 *
 * Evidence: HS_DESC* event shapes, HS_DESC_CONTENT body, HSPOST/HSFETCH gates.
 */
class HsControlElevationTest {
    private val onion =
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz234567.onion"

    @Test
    fun `desc event lifecycle strings`() {
        val req = HsControl.descEventRequested(onion, "blindedB64", "hsdirid", hsDirIndexHex = "aabb")
        assertTrue(req.startsWith("HS_DESC REQUESTED"))
        assertTrue(req.contains("NO_AUTH"))
        assertTrue(req.endsWith("aabb"))
        val fail = HsControl.descEventFailed(onion, "hsdirid", HsControl.FailReason.NOT_FOUND)
        assertTrue(fail.contains("FAILED") && fail.contains("NOT_FOUND"))
        assertTrue(HsControl.descEventCreated(onion, "b64").contains("CREATED"))
        assertTrue(HsControl.descEventUpload(onion, "d", "b").contains("UPLOAD"))
        assertTrue(HsControl.descEventUploaded(onion, "d").contains("UPLOADED"))
    }

    @Test
    fun `HS_DESC_CONTENT with body`() {
        val body = "hs-descriptor 3\n"
        val ev = HsControl.descEventContent(onion, "dir", body)
        assertTrue(ev.startsWith("HS_DESC_CONTENT"))
        assertTrue(ev.contains(body.trim()))
        assertTrue(ev.trimEnd().endsWith("."))
        assertEquals(
            "HS_DESC_CONTENT $onion NO_AUTH dir (12 bytes)",
            HsControl.descEventContent(onion, "dir", 12),
        )
    }

    @Test
    fun `hspost hsfetch gates and SERVER hints`() {
        assertTrue(HsControl.hsPostAccepted("x", onion))
        assertFalse(HsControl.hsPostAccepted("", onion))
        assertFalse(HsControl.hsPostAccepted("x", "not-onion"))
        assertTrue(HsControl.hsFetchAccepted(onion))
        assertTrue(HsControl.hsFetchAccepted("ab".repeat(32)))
        assertFalse(HsControl.hsFetchAccepted("short"))
        assertEquals(
            listOf("a.onion", "b"),
            HsControl.parseServerHints(listOf("SERVER=a.onion", "HSDir=b", "other")),
        )
    }
}
