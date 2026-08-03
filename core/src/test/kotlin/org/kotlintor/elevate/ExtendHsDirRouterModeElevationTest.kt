package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.circuit.HopKeys
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.DirList
import org.kotlintor.dir.RouterStatus
import org.kotlintor.hs.HsCache
import org.kotlintor.hs.HsDescriptorInner
import org.kotlintor.hs.HsDescriptorOuter
import org.kotlintor.relay.RouterMode
import org.kotlintor.util.hexToBytes
import java.nio.file.Path
import java.time.Instant

/**
 * Elevates inventory rows:
 * - L1:core/or/extendinfo.c / L2:extend_info_t
 * - L1:feature/hs/hs_cache.c
 * - L1:feature/nodelist/dirlist.c / L2:dir_server_t
 * - L1:feature/relay/routermode.c
 */
class ExtendHsDirRouterModeElevationTest {
    private val dataDir: Path = Path.of("/tmp/ktor-elevate-test")

    @Test
    fun `extend_info from router and ntor helpers`() {
        val id = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val rs = RouterStatus(
            nickname = "Test",
            identity = id,
            digest = id,
            publication = Instant.EPOCH,
            ip = "1.2.3.4",
            orPort = 9001,
            dirPort = 9030,
            flags = setOf("Running", "Valid"),
            version = null,
            proto = mapOf("Relay" to "1-6", "FlowCtrl" to "1-2"),
            bandwidth = 1000,
            ntorOnionKey = ByteArray(32) { 1 },
        )
        val ei = ExtendInfo.fromRouterStatus(rs, supportsNtorV3 = true, enableCgo = true)
        assertTrue(ei.supportsNtor())
        assertTrue(ei.supportsNtorV3Flag())
        assertEquals("1.2.3.4", ei.pickOrPort()?.host)
        assertFalse(ExtendInfo.addrAllowed("10.0.0.1", allowPrivate = false))
        assertTrue(ExtendInfo.addrAllowed("10.0.0.1", allowPrivate = true))
        val keys = ei.toHopKeys()
        assertNotNull(keys)
        val fromHop = ExtendInfo.fromHop("Test", rs.fingerprintHex, "1.2.3.4", 9001, keys!!)
        assertEquals(ei.fingerprintHex(), fromHop.fingerprintHex())
    }

    @Test
    fun `hs_cache store lookup clean oom`() {
        val cache = HsCache(maxEntries = 2, maxLifetimeSec = 3600)
        assertTrue(cache.storeAsDir("ABCD", "desc-one"))
        assertEquals("desc-one", cache.lookupAsDir("abcd"))
        cache.markDownloadedAsDir("ABCD")
        val outer = HsDescriptorOuter(3, "", 1, ByteArray(0), null, "raw")
        val inner = HsDescriptorInner(emptyList(), emptyList(), false, "inner")
        cache.storeAsClient("ff".repeat(32), outer, inner, encoded = "enc")
        assertNotNull(cache.lookupAsClient("FF".repeat(32)))
        cache.noteIntroState("FF".repeat(32), "11".repeat(32), timedOut = true)
        assertEquals(1, cache.findIntroState("FF".repeat(32), "11".repeat(32))?.unreachableCount)
        cache.storeAsDir("BBBB", "two")
        cache.storeAsDir("CCCC", "three")
        assertTrue(cache.dirSize() <= 2)
        val removed = cache.handleOom(1)
        assertTrue(removed >= 1)
    }

    @Test
    fun `dirlist defaults and fallback parse`() {
        val list = DirList.withDefaults()
        assertTrue(list.trusted().size >= 8)
        assertNotNull(list.trustedByV3Digest(list.trusted().first().v3IdentityHex!!))
        val fb = list.parseFallbackLine("198.51.100.1:80 orport=443 id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb weight=1.5")
        assertNotNull(fb)
        list.add(fb!!)
        assertEquals(1, list.fallbacks().size)
        assertEquals(443, list.fallbacks().first().orPort)
    }

    @Test
    fun `routermode mirrors ORPort ClientOnly BridgeRelay ExitRelay`() {
        val client = TorConfig(dataDirectory = dataDir)
        assertFalse(RouterMode.serverMode(client))
        val relay = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            orPort = ListenSpec("0.0.0.0", 9001),
            exitRelay = true,
        )
        assertTrue(RouterMode.serverMode(relay))
        assertTrue(RouterMode.publicServerMode(relay))
        assertTrue(RouterMode.exitMode(relay))
        val bridge = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            orPort = ListenSpec("0.0.0.0", 9001),
            bridgeRelay = true,
        )
        assertFalse(RouterMode.publicServerMode(bridge))
        val auth = TorConfig(dataDirectory = dataDir, authoritativeDirectory = true)
        assertTrue(RouterMode.dirServerMode(auth))
        assertTrue(RouterMode.summary(relay).contains("server=true"))
    }
}
