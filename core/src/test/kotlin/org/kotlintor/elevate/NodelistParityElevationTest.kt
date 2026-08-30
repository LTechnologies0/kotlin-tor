package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.AuthCert
import org.kotlintor.dir.AuthorityCert
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.Describe
import org.kotlintor.dir.DirList
import org.kotlintor.dir.DirServer
import org.kotlintor.dir.Microdesc
import org.kotlintor.dir.NetworkStatus
import org.kotlintor.dir.Nickname
import org.kotlintor.dir.NodeFamily
import org.kotlintor.dir.NodeList
import org.kotlintor.dir.NodeSelect
import org.kotlintor.dir.RouterList
import org.kotlintor.dir.RouterStatus
import java.time.Instant

/**
 * Elevates feature/nodelist L3 ops (D2→D3) via OP_SEED_DEPTH — batch 1.
 */
class NodelistParityElevationTest {
    @Test
    fun `authcert dirlist networkstatus describe L3 batch`() {
        AuthCert.authcertFreeAll()
        val mat = AuthorityCert.generate(1024)
        val doc = mat.formatCertificate(
            published = Instant.parse("2024-01-01T00:00:00Z"),
            expires = Instant.parse("2024-06-01T00:00:00Z"),
        )
        val parsed = AuthCert.parse(doc)
        assertTrue(AuthCert.verify(parsed))
        AuthCert.put(parsed)
        val idHex = parsed.identityKeyDigest.joinToString("") { "%02x".format(it) }
        val skHex = parsed.signingKeyDigest.joinToString("") { "%02x".format(it) }
        assertEquals(parsed, AuthCert.authorityCertGetByDigests(idHex, skHex))
        assertEquals(parsed, AuthCert.authorityCertGetBySkDigest(skHex))
        assertEquals(parsed, AuthCert.authorityCertGetNewestById(idHex))
        assertEquals(1, AuthCert.authorityCertGetAll().size)
        assertFalse(AuthCert.authorityCertIsDenylisted(skHex))
        AuthCert.authorityCertDenylistAdd(skHex)
        assertTrue(AuthCert.authorityCertIsDenylisted(skHex))
        AuthCert.authorityCertDlFailed(idHex, skHex)
        AuthCert.authorityCertDlFailed(idHex, skHex)
        assertTrue(AuthCert.authorityCertDlLooksUncertain(idHex))
        assertTrue(AuthCert.authorityCertsFetchMissing(listOf("deadbeef")).isNotEmpty())
        assertEquals(null, AuthCert.authorityCertFree_(parsed))
        AuthCert.authcertFreeAll()

        assertEquals("download", DirList.authDirportUsageForPurpose("fetch"))
        assertEquals("upload", DirList.authDirportUsageForPurpose("upload"))
        assertEquals("voting", DirList.authDirportUsageForPurpose("upload_vote"))
        DirList.dirlistFreeAll()
        DirList.clearDirServers()
        DirList.dirServerAdd(
            DirServer("auth1", "1.2.3.4", 80, 9001, v3IdentityHex = "AA".repeat(20), isAuthority = true),
        )
        assertEquals(1, DirList.getNAuthorities())
        DirList.fallbackDirServerNewAndAdd("5.6.7.8", 80, 9001, "BB".repeat(20))
        DirList.dirlistFreeAll()

        val pick = NodeSelect.chooseArrayElementByWeight(listOf("a", "b"), listOf(1.0, 0.0))
        assertEquals("a", pick)

        val rs = RouterStatus(
            nickname = "Test",
            identity = ByteArray(20) { 1 },
            digest = ByteArray(20) { 2 },
            publication = Instant.parse("2024-01-01T00:00:00Z"),
            ip = "9.9.9.9",
            orPort = 9001,
            dirPort = 80,
            flags = setOf("Running", "Valid", "Fast"),
            version = null,
            proto = emptyMap(),
            bandwidth = 1000,
        )
        assertTrue(NetworkStatus.clientWouldUseRouter(rs))
        assertEquals(0, NetworkStatus.compareDigestToRouterstatusEntry(rs.identity, rs))
        assertEquals(0, NetworkStatus.compareDigestToVoteRouterstatusEntry(rs.identity, rs))
        assertTrue(NetworkStatus.compareDigestToRouterstatusEntry(ByteArray(20) { 9 }, rs) != 0)
        AuthCert.authorityCertsFetchMissing(listOf("x"))
        assertTrue(NetworkStatus.consensusIsWaitingForCerts())
        val sig = NetworkStatus.DocumentSignature("id", "sk", ByteArray(8) { 3 })
        assertEquals(8, NetworkStatus.documentSignatureDup(sig).signature.size)
        assertEquals(null, NetworkStatus.documentSignatureFree_(sig))

        NodeList.noteLoadingProgress(5, 10)
        assertEquals(50, NodeList.countLoadingDescriptorsProgress())
        assertTrue(NodeList.getDirInfoStatusString().contains("pct="))

        val rl = RouterList()
        rl.add(rs)
        assertTrue(rl.dumpRouterlistMemUsage().contains("n=1"))
        assertTrue(RouterList.escRouterInfo(rs).contains("Test"))
        assertTrue(Describe.extendInfoDescribe(rs.fingerprintHex, rs.ip, rs.orPort, rs.nickname).contains("Test"))
        assertTrue(Describe.formatNodeDescription(rs.nickname, rs.fingerprintHex).contains("Test"))
        assertEquals(0.5, NodeSelect.fracNodesWithDescriptors(5, 10), 1e-9)
        assertTrue(NetworkStatus.getinfoHelperNetworkstatus(null).contains("unavailable"))
        val fb = DirList.fallbackDirServerNew("1.1.1.1", 80, 9001, "CC".repeat(20))
        assertTrue(fb.isFallback)
        assertEquals(null, RouterList.extrainfoFree_("ei-body"))

        // Batch 2: microdesc / nickname / downloads / networkstatus / node_*
        Microdesc.microdescFreeAll()
        assertTrue(Microdesc.getMicrodescCache().isEmpty())
        Microdesc.microdescsAddToCache("aa".repeat(32), "onion-key\n")
        assertEquals(2, Microdesc.microdescsAddListToCache(listOf("bb".repeat(32) to "x", "cc".repeat(32) to "y")))
        assertNotNull(Microdesc.microdescCacheLookupByDigest256("aa".repeat(32)))
        assertEquals(1, Microdesc.microdescListMissingDigest256(listOf("aa".repeat(32), "dd".repeat(32))).size)
        assertEquals(0, Microdesc.microdescCacheClean(maxAgeMs = Long.MAX_VALUE))
        assertTrue(Microdesc.microdescCacheRebuild() >= 1)
        assertTrue(Microdesc.microdescCacheReload() >= 1)
        assertEquals(3, Microdesc.microdescCheckCounts().first)
        Microdesc.microdescNoteOutdatedDirserver("dead")
        assertTrue(Microdesc.microdescRelayIsOutdatedDirserver("dead"))
        Microdesc.microdescResetOutdatedDirserversList()
        assertFalse(Microdesc.microdescRelayIsOutdatedDirserver("dead"))
        assertEquals(null, Microdesc.microdescFree_(Microdesc.microdescCacheLookupByDigest256("aa".repeat(32))))
        Microdesc.microdescCacheClear()
        Microdesc.microdescFreeAll()

        assertTrue(Nickname.isLegalNickname("TestRelay"))
        assertTrue(Nickname.isLegalHexdigest("AA".repeat(20)))
        assertTrue(Nickname.isLegalNicknameOrHexdigest("TestRelay"))
        val dig = "AB".repeat(20)
        assertEquals(dig, RouterList.hexDigestNicknameDecode("\$$dig~Nick"))
        assertFalse(RouterList.hexDigestNicknameMatches("\$$dig=Nick", dig, "Nick"))
        assertTrue(RouterList.hexDigestNicknameMatches("\$$dig~Nick", dig, "Nick"))
        assertEquals(20, RouterList.hexdigestToDigest(dig)!!.size)
        assertEquals(2, RouterList.launchDescriptorDownloads(listOf("d1", "d2")))
        assertEquals(2, RouterList.listPendingDownloads().size)
        NodeList.processList().notePendingMicrodesc("m1")
        assertTrue(RouterList.listPendingMicrodescDownloads().contains("m1"))
        DirList.markAllDirserversUp()
        assertEquals(null, NodeList.linkSpecifierSmartlistFree_(listOf(ByteArray(2))))

        val now = Instant.parse("2024-06-01T00:00:00Z")
        val cons = Consensus(
            validAfter = now.minusSeconds(3600),
            freshUntil = now.plusSeconds(3600),
            validUntil = now.plusSeconds(7200),
            relays = listOf(rs),
            raw = "network-status-version 3\ndirectory-signature sha1 aa bb\n-----BEGIN SIGNATURE-----\nAA==\n-----END SIGNATURE-----\n",
            params = mapOf("Wgg" to 1L, "bwweightscale" to 10000L),
        )
        assertTrue(NetworkStatus.networkstatusCheckConsensusSignature(cons))
        assertFalse(
            NetworkStatus.networkstatusCheckConsensusSignature(
                cons.copy(raw = "network-status-version 3\n"),
            ),
        )
        assertTrue(NetworkStatus.networkstatusCheckDocumentSignature(sig))
        assertTrue(NetworkStatus.networkstatusConsensusCanUseMultipleDirectories())
        NetworkStatus.networkstatusNoteConsensusDownloadStart()
        assertTrue(NetworkStatus.networkstatusConsensusIsAlreadyDownloading())
        NetworkStatus.networkstatusConsensusDownloadFailed()
        assertTrue(NetworkStatus.networkstatusConsensusReasonablyLive(cons, now))
        assertTrue(NetworkStatus.networkstatusIsLive(cons, now))
        assertEquals(1L, NetworkStatus.networkstatusGetBwWeight(cons, "Wgg"))
        assertEquals("ns", NetworkStatus.networkstatusGetFlavorName(0))
        assertEquals(1L, NetworkStatus.networkstatusGetOverridableParam(cons, "Wgg", 0))
        assertEquals(10000L, NetworkStatus.networkstatusGetWeightScaleParam(cons))
        NetworkStatus.networkstatusNoteVoter("vv", "Voter")
        assertEquals("Voter", NetworkStatus.networkstatusGetVoterById("vv"))
        assertNotNull(NetworkStatus.networkstatusGetVoterSigByAlg(listOf(sig), "sha1"))
        assertTrue(NetworkStatus.networkstatusGetinfoByPurpose("general").contains("purpose"))
        assertTrue(NetworkStatus.networkstatusGetinfoHelperSingle(rs).contains("Test"))
        NetworkStatus.networkstatusMapCachedConsensus(cons)
        NetworkStatus.networkstatusNoteCertsArrived()
        NetworkStatus.networkstatusFreeAll()

        assertTrue(NodeList.nodeDescribe(rs).contains("Test"))
        assertTrue(Describe.nodeDescribe(rs).contains("Test"))
        assertEquals("9.9.9.9", NodeList.nodeGetAddr(rs))
        assertTrue(NodeList.nodeGetAddressString(rs).contains("9001"))
        assertEquals(1, NodeList.nodeGetAllOrports(rs).size)
        NodeList.processList().add(rs)
        assertNotNull(NodeList.nodeGetByHexId(rs.fingerprintHex))
        assertEquals("Test", NodeList.nodeGetNickname(rs))
        assertEquals(null, NodeList.nodeGetPlatform(rs))
        assertEquals(9001, NodeList.nodeGetPrefOrport(rs).second)
        assertEquals(9001, NodeList.nodeGetPrimOrport(rs).second)
        assertEquals(80, NodeList.nodeGetPrefDirport(rs).second)
        assertEquals(80, NodeList.nodeGetPrimDirport(rs).second)
        assertEquals(null, NodeList.nodeGetPrefIpv6Orport(rs))
        assertEquals(null, NodeList.nodeGetPrefIpv6Dirport(rs))
        assertEquals(20, NodeList.nodeGetRsaIdDigest(rs).size)
        assertEquals(null, NodeList.nodeGetCurve25519OnionKey(rs))
        assertFalse(NodeList.nodeEd25519IdMatches(rs, ByteArray(32)))
        assertFalse(NodeList.nodeAllowsSingleHopExits(rs))
        assertEquals("general", NodeList.nodeGetPurpose(rs))
        assertEquals(0L, NodeList.nodeGetDeclaredUptime(rs))
        assertEquals(null, NodeList.nodeGetMutableByEd25519Id("00".repeat(32)))
        assertTrue(NodeList.nodeFamilyListContains("\$ABCD family", "ABCD"))
        assertNotNull(NodeSelect.nodeSlChooseByBandwidth(listOf(rs)))
        val nf = NodeFamily.parse("\$${rs.fingerprintHex} OtherNick")!!
        assertTrue(NodeFamily.nodefamilyContainsNode(nf, rs.fingerprintHex))
        assertTrue(NodeFamily.nodefamilyContainsRsaId(nf, rs.fingerprintHex))
        assertNotNull(NodeFamily.nodefamilyCanonicalize("\$${rs.fingerprintHex}"))
        assertTrue(NodeFamily.nodefamilyAddNodesToSmartlist(nf).isNotEmpty())
    }
}
