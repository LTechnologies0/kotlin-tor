package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.or.CachedDir
import org.kotlintor.or.DescStore
import org.kotlintor.or.MicrodescCache
import org.kotlintor.or.SocksRequest
import org.kotlintor.or.TorVersion
import org.kotlintor.or.VegasParams

/**
 * Elevates L2 struct mirrors in OrStructMirrors.kt (D0 to D2 via STRUCT_HINTS).
 * Inventory: selected L2 core/or struct rows plus control_cmd_args_t.
 */
class OrStructMirrorsElevationTest {
    @Test
    fun `cached dir desc store microdesc socks version vegas`() {
        val cd = CachedDir("consensus-body")
        assertTrue(cd.dir.isNotEmpty())
        val store = DescStore()
        store.store("AABB", "desc")
        assertEquals("desc", store.lookup("aabb"))
        val md = MicrodescCache()
        md.put("deadbeef", "@last-listed 2020-01-01")
        assertEquals("@last-listed 2020-01-01", md.get("DEADBEEF"))
        val socks = SocksRequest(1, "example.com", 443)
        assertEquals(443, socks.port)
        assertEquals("0.4.8-stable", TorVersion.parse("0.4.8")?.toString())
        assertNotNull(VegasParams())
        assertEquals(ListenSpec("127.0.0.1", 9050).port, 9050)
    }
}
