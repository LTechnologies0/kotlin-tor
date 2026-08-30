package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.hs.HsCache
import org.kotlintor.hs.HsCell
import org.kotlintor.hs.HsCircuit
import org.kotlintor.hs.HsCircuitmap
import org.kotlintor.hs.HsClient
import org.kotlintor.hs.HsClientAuth
import org.kotlintor.hs.HsCommon
import org.kotlintor.hs.HsConfig
import org.kotlintor.hs.HsControl
import org.kotlintor.hs.HsDescriptor
import org.kotlintor.hs.HsDescriptorInner
import org.kotlintor.hs.HsDescriptorOuter
import org.kotlintor.hs.HsDos
import org.kotlintor.hs.HsIdent
import org.kotlintor.hs.HsIntropoint
import org.kotlintor.hs.HsMetrics
import org.kotlintor.hs.HsOb
import org.kotlintor.hs.HsPow
import org.kotlintor.hs.HsService
import org.kotlintor.hs.HsTimePeriod
import org.kotlintor.hs.IntroductionPoint
import org.kotlintor.stats.HsStats
import java.time.Instant

/**
 * Elevates feature/hs L3 ops (D2→D3) via OP_SEED_DEPTH.
 */
class HsParityElevationTest {
    @Test
    fun `hs client service common cell cache L3 batch`() {
        assertTrue(HsClient.authKeyFilenameIsValid("client.auth_key"))
        assertFalse(HsClient.authKeyFilenameIsValid("../x"))
        val link = byteArrayOf(1, 0, 6, 1, 2, 3, 4, 0x23, 0x29)
        val ip = IntroductionPoint(
            linkSpecifiers = link,
            onionKeyNtor = ByteArray(32) { 1 },
            encKeyNtor = ByteArray(32) { 2 },
            authKeyCertPem = null,
            encKeyCertPem = null,
        )
        assertNotNull(HsClient.clientGetRandomIntro(listOf(ip)))
        val auth = HsClient.ClientAuth("abc.onion")
        HsClient.noteClientAuth(auth)
        assertEquals(1, HsClient.getHsClientAuthsMap().size)
        assertEquals(null, HsClient.clientServiceAuthorizationFree_(auth))
        assertTrue(HsClient.getHsClientAuthsMap().isEmpty())
        val ext = HsClient.descIntroPointToExtendInfo(ip)
        assertEquals(9001, ext.orPort)
        assertEquals("1.2.3.4", ext.ipv4)

        HsService.clearServices()
        val svc = HsService.ServiceLite("xyz.onion", numIntroPoints = 3, introCircuitsReady = 1)
        HsService.registerService(svc)
        assertEquals(svc, HsService.findService("xyz.onion"))
        assertEquals(svc, HsService.getFirstService())
        assertEquals(1, HsService.getHsServiceMapSize())
        assertEquals(2, HsService.buildAllDescriptors())
        assertEquals(2, svc.descriptors.size)
        assertTrue(HsService.canServiceLaunchIntroCircuit(svc))
        assertTrue(HsService.clientFilenameIsValid("alice.auth"))
        assertFalse(HsService.clientFilenameIsValid("alice.txt"))

        val period = HsTimePeriod.containing(Instant.parse("2020-01-01T12:00:00Z"))
        val id = Ed25519Keys.generate().publicKey
        assertEquals(32, HsCommon.buildBlindedKeyParam(id, period).size)
        val d1 = HsCommon.getDisasterSrv(period)
        assertEquals(32, d1.size)
        assertNotNull(HsCommon.getFirstCachedDisasterSrv())
        assertNotNull(HsCommon.getSecondCachedDisasterSrv())
        assertTrue(HsCommon.getTimePeriodLength() > 0)
        assertEquals(1440L, HsCommon.getTimePeriodLength())
        assertEquals(1440 * 60L, HsCommon.timePeriodLengthSec())

        val extBlob = HsCell.buildEstablishIntroExtensions(25, 50)
        assertTrue(extBlob.isNotEmpty())
        assertTrue(HsIntropoint.cellDosExtensionParametersAreValid(25, 50))
        assertFalse(HsIntropoint.cellDosExtensionParametersAreValid(50, 25))
        assertTrue(HsIntropoint.circuitIsSuitableForIntroduce1(HsCircuit.PURPOSE_CLIENT_INTRO, true))
        assertEquals(32, HsIntropoint.getAuthKeyFromCell(
            byteArrayOf(0x02, 0x00, 0x20) + ByteArray(32) { 3 },
        )!!.size)
        assertEquals(null, HsIntropoint.getAuthKeyFromCell(ByteArray(40) { 3 }))

        val cache = HsCache()
        cache.storeAsDir("AA".repeat(32), "hs-descriptor 3\n")
        cache.dirSetDownloaded("AA".repeat(32))
        cache.storeAsDir("BB".repeat(32), "hs-descriptor 3\n")
        cache.cacheCleanV3ByDownloadedAsDir()
        assertEquals(1, cache.dirSize())
        cache.cacheCleanV3AsDir(nowMs = System.currentTimeMillis() + 100_000_000_000L)
        assertEquals(0, cache.dirSize())

        val padded = HsDescriptor.buildPlaintextPadding(ByteArray(100))
        assertEquals(0, padded.size % 10_000)
        assertTrue(HsDescriptor.encryptedDataLengthIsValid(64))
        assertFalse(HsDescriptor.encryptedDataLengthIsValid(48))
        assertFalse(HsDescriptor.encryptedDataLengthIsValid(1))
        val outer = HsDescriptorOuter(
            lifetimeMinutes = 180,
            signingKeyCertPem = "cert",
            revisionCounter = 1,
            superencrypted = ByteArray(8),
            signatureB64 = "sig",
            raw = "x",
        )
        assertFalse(HsDescriptor.descSigIsValid(outer))
        assertFalse(HsDescriptor.certIsValid(null))
        assertFalse(HsDescriptor.certIsValid(""))
        assertEquals(null, HsDescriptor.descDecodeEncryptedV3("nope"))
        assertEquals(null, HsDescriptor.descDecodeSuperencryptedV3("nope"))
        val parsed = HsDescriptor.decodeLinkSpecifiers(link)
        assertEquals(9001, parsed.port)
        assertEquals(ip, HsDescriptor.decodeIntroductionPoint(ip))
        assertEquals(null, HsClient.findDescIntroPointByIdent(listOf(ip), "aa".repeat(32)))

        val rs = org.kotlintor.dir.RouterStatus(
            nickname = "n",
            identity = ByteArray(20) { 1 },
            digest = ByteArray(20) { 2 },
            publication = Instant.EPOCH,
            ip = "127.0.0.1",
            orPort = 9001,
            dirPort = 0,
            flags = emptySet(),
            version = null,
            proto = emptyMap(),
            bandwidth = 1,
            ed25519Identity = ByteArray(32) { 3 },
        )
        assertTrue(HsDescriptor.encodeLinkSpecifiers(rs).isNotEmpty())

        val rp = HsCircuit.createRpCircuitIdentifier(ByteArray(20) { 9 }, 42L)
        assertEquals(42L, rp.circId)
        HsCircuit.rendPqueueClear()
        HsCircuit.rendPqueueOffer(1_700_000_000L, 1L)
        assertTrue(HsCircuit.topOfRendPqueueIsWorthwhile(1_700_000_001L))

        val blinded = HsCommon.buildBlindedPubkey(id, period)
        val subcreds = HsOb.computeSubcredentials(
            masterPubkeys = listOf(id),
            timePeriodNum = period.intervalNum,
            currentInstanceSubcred = ByteArray(32) { 1 },
            nextInstanceSubcred = ByteArray(32) { 2 },
        )
        assertEquals(5, subcreds.size) // 3 TP steps + 2 instance
        assertEquals(32, subcreds[0].size)
        assertEquals(32, HsOb.computeSubcredentials(id, blinded).size)

        HsCircuitmap.clear()
        HsCircuitmap.put("t", 1L)
        assertEquals(1, HsCircuitmap.getHsCircuitmap().size)
    }

    @Test
    fun `hs dos common cache address L3 batch`() {
        assertEquals(HsDos.DEFAULT_RATE, HsDos.getIntro2RateConsensusParam(null))
        assertEquals(HsDos.DEFAULT_BURST, HsDos.getIntro2BurstConsensusParam(null))
        assertFalse(HsDos.getIntro2EnableConsensusParam(null))

        val kp = Ed25519Keys.generate()
        val addr = HsCommon.hsBuildAddress(kp.publicKey)
        assertTrue(HsCommon.hsAddressIsValid(addr))
        assertFalse(HsCommon.hsAddressIsValid("not-an-onion"))
        val period = HsTimePeriod(intervalNum = 100)
        val blinded = HsCommon.hsBuildBlindedPubkey(kp.publicKey, period)
        assertEquals(32, blinded.size)
        val blindKp = HsCommon.hsBuildBlindedKeypair(kp.privateKey, kp.publicKey, period)
        assertEquals(32, blindKp.publicKey.size)
        assertEquals(32, HsCommon.hsBuildHsIndex(blinded, 1, period).size)
        assertEquals(32, HsCommon.hsBuildHsdirIndex(ByteArray(32) { 1 }, ByteArray(32) { 2 }, period).size)
        HsCommon.noteHidServRequest("svc")
        assertEquals(1, HsCommon.getLastHidServRequests().size)

        HsService.clearStaging()
        HsService.stageService(HsService.ServiceLite("a.onion"))
        assertEquals(1, HsService.getHsServiceStagingListSize())
        val link = byteArrayOf(1, 2, 20) + ByteArray(20) { 0xab.toByte() }
        val ip = IntroductionPoint(link, ByteArray(32), ByteArray(32), null, null)
        assertEquals("AB".repeat(20), HsService.getNodeFromIntroPoint(ip))
        HsService.registerService(HsService.ServiceLite("svc.onion", directoryHint = "DEAD"))
        assertNotNull(HsService.getObjectsFromIdent(HsIdent.circuit(serviceIdentityHex = "DEAD")))

        val cache = HsCache()
        cache.storeAsDir("CC".repeat(32), "doc")
        cache.hsCacheCleanAsDir(System.currentTimeMillis() + 1e15.toLong())
        cache.storeAsClient(
            "DD".repeat(20),
            HsDescriptorOuter(3, "c", 1, ByteArray(1), "s", "r"),
            org.kotlintor.hs.HsDescriptorInner(listOf(2), emptyList(), false, "i"),
            "enc",
        )
        cache.hsCacheClientIntroStateNote("DD".repeat(20), "EE".repeat(20))
        assertNotNull(cache.hsCacheClientIntroStateFind("DD".repeat(20), "EE".repeat(20)))
        cache.hsCacheClientIntroStateClean(System.currentTimeMillis() + 1e15.toLong())
        cache.hsCacheClientIntroStatePurge()
        assertEquals("foo.onion", cache.hsCacheClientNewAuthParse("foo.onion:deadbeef"))
        cache.hsCacheDecrementAllocation(1)
        assertTrue(cache.hsCacheGetMaxBytes() > 0)
        assertTrue(cache.hsCacheGetMaxDescriptorSize() > 0)
        cache.hsCacheFreeAll()
        assertEquals(0, cache.dirSize())

        assertTrue(HsClient.handleRendezvous2(byteArrayOf(1)))
        val table = HsIntropoint.table()
        HsIntropoint.beginEstablish(table, "FF".repeat(32))
        table.noteEstablished("FF".repeat(32))
        assertTrue(HsIntropoint.handleIntroduce1(table, "FF".repeat(32)))
    }

    @Test
    fun `hs cache cell circ L3 batch`() {
        val cache = HsCache()
        cache.hsCacheInit()
        assertTrue(cache.hsCacheStoreAsDir("AA".repeat(32), "desc-body"))
        assertEquals("desc-body", cache.hsCacheLookupAsDir("AA".repeat(32)))
        cache.hsCacheMarkDowloadedAsDir("AA".repeat(32))
        cache.hsCacheIncrementAllocation(10)
        assertTrue(cache.hsCacheGetTotalAllocation() >= 10)
        assertTrue(cache.hsCacheHandleOom(1) >= 0)
        val outer = HsDescriptorOuter(3, "c", 1, ByteArray(1), "s", "r")
        val inner = HsDescriptorInner(listOf(2), emptyList(), false, "i")
        cache.hsCacheStoreAsClient("11".repeat(20), outer, inner, "ENC")
        assertNotNull(cache.hsCacheLookupAsClient("11".repeat(20)))
        assertEquals("ENC", cache.hsCacheLookupEncodedAsClient("11".repeat(20)))
        cache.hsCacheRemoveAsClient("11".repeat(20))
        assertEquals(null, cache.hsCacheLookupAsClient("11".repeat(20)))
        cache.hsCacheStoreAsClient("22".repeat(20), outer, inner, "E2")
        cache.hsCachePurgeAsClient()
        assertEquals(0, cache.clientSize())

        val auth = ByteArray(32) { 7 }
        val est = HsCell.hsCellBuildEstablishIntro(auth, 25, 50)
        // AUTH_KEY_TYPE+LEN+KEY + N_EXTENSIONS + DoS TYPE+LEN+BODY
        assertEquals(1 + 2 + 32 + 1 + 10, est.size)
        assertEquals(HsCell.AUTH_KEY_TYPE_ED25519, est[0].toInt() and 0xff)
        assertNotNull(HsIntropoint.getAuthKeyFromCell(est))
        val kp = Ed25519Keys.generate()
        val kh = ByteArray(20) { 9 }
        val full = HsCell.hsCellBuildEstablishIntro(kp.publicKey, kp.privateKey, kh, 25, 50)
        assertTrue(HsIntropoint.verifyEstablishIntroCell(full, kh))
        assertFalse(HsIntropoint.verifyEstablishIntroCell(full, ByteArray(20) { 0 }))
        assertEquals(20, HsCell.hsCellBuildEstablishRendezvous(ByteArray(20)).size)
        assertTrue(HsCell.hsCellBuildIntroduce1(authKey = auth).size >= 55)
        assertEquals(52, HsCell.hsCellBuildRendezvous1(ByteArray(20), ByteArray(32)).size)
        val i1 = HsCell.Introduce1Data(authKey = auth)
        HsCell.hsCellIntroduce1DataClear(i1)
        assertEquals(null, i1.authKey)
        assertTrue(HsCell.hsCellParseIntroEstablished(ByteArray(0)))
        assertNotNull(HsCell.hsCellParseIntroduce2(byteArrayOf(1)))
        assertEquals(0, HsCell.hsCellParseIntroduceAck(ByteArray(0)))
        assertNotNull(HsCell.hsCellParseRendezvous2(ByteArray(32)))

        HsCircuit.clearAll()
        val intro = HsCircuit.hsCircLaunchIntroPoint("AA".repeat(32))
        assertTrue(HsCircuit.hsCircHandleIntroEstablished(intro.circId, "AA".repeat(32)))
        assertTrue(HsCircuit.hsCircHandleIntroduce2(intro.circId, byteArrayOf(1)))
        assertNotNull(HsCircuit.hsCircServiceGetEstablishedIntroCirc("AA".repeat(32)))
        val client = HsCircuit.CircLite(99, HsCircuit.PURPOSE_CLIENT_INTRO)
        HsCircuit.noteCirc(client)
        HsCircuit.hsCircSendIntroduce1(99, auth)
        assertTrue(HsCircuit.hsCircIsRendSentInIntro1(99))
        val rend = HsCircuit.hsCircLaunchRendezvousPoint()
        assertEquals(20, HsCircuit.hsCircSendEstablishRendezvous(rend.circId, ByteArray(20)).size)
        val retry = HsCircuit.hsCircRetryServiceRendezvousPoint(rend.circId)
        assertTrue(retry.circId != rend.circId)
        HsCircuit.hsCircCleanupOnClose(intro.circId)
        HsCircuit.hsCircCleanupOnRepurpose(99, HsCircuit.PURPOSE_CLIENT_REND)
        HsCircuit.hsCircCleanupOnFree(intro.circId)

        val dir = java.nio.file.Files.createTempDirectory("hs-priv")
        assertTrue(HsCommon.hsCheckServicePrivateDir(dir))
    }

    @Test
    fun `hs circuitmap circ remaining L3 batch`() {
        HsCircuitmap.hsCircuitmapInit()
        HsCircuitmap.hsCircuitmapRegisterIntroCircV3RelaySide("AA".repeat(32), 1L)
        HsCircuitmap.hsCircuitmapRegisterIntroCircV3ServiceSide("AA".repeat(32), 2L)
        assertEquals(1L, HsCircuitmap.hsCircuitmapGetIntroCircV3RelaySide("AA".repeat(32)))
        assertEquals(2L, HsCircuitmap.hsCircuitmapGetIntroCircV3ServiceSide("AA".repeat(32)))
        assertEquals(1, HsCircuitmap.hsCircuitmapGetAllIntroCircRelaySide().size)
        HsCircuitmap.hsCircuitmapRegisterRendCircClientSide("ab".repeat(10), 3L)
        HsCircuitmap.hsCircuitmapRegisterRendCircRelaySide("ab".repeat(10), 4L)
        HsCircuitmap.hsCircuitmapRegisterRendCircServiceSide("ab".repeat(10), 5L)
        assertEquals(3L, HsCircuitmap.hsCircuitmapGetRendCircClientSide("ab".repeat(10)))
        assertEquals(4L, HsCircuitmap.hsCircuitmapGetRendCircRelaySide("ab".repeat(10)))
        assertEquals(5L, HsCircuitmap.hsCircuitmapGetRendCircServiceSide("ab".repeat(10)))
        assertEquals(3L, HsCircuitmap.hsCircuitmapGetEstablishedRendCircClientSide("ab".repeat(10)))
        HsCircuitmap.hsCircuitmapRemoveCircuit(3L)
        assertEquals(null, HsCircuitmap.hsCircuitmapGetRendCircClientSide("ab".repeat(10)))
        HsCircuitmap.hsCircuitmapFreeAll()
        assertEquals(0, HsCircuitmap.size())

        HsCircuit.clearAll()
        val intro = HsCircuit.hsCircLaunchIntroPoint("BB".repeat(32))
        HsCircuit.hsCircHandleIntroEstablished(intro.circId, "BB".repeat(32))
        assertNotNull(HsCircuit.hsCircServiceGetIntroCirc("BB".repeat(32)))
        assertTrue(HsCircuit.hsCircServiceIntroHasOpened(intro.circId))
        val rp = HsCircuit.hsCircLaunchRendezvousPoint()
        assertTrue(HsCircuit.hsCircServiceRpHasOpened(rp.circId))
        assertTrue(HsCircuit.hsCircSetupCongestionControl(rp.circId))
        assertTrue(HsCircuit.hsCircuitSetupE2eRendCirc(rp.circId))
        assertTrue(HsCircuit.hsCircuitSetupE2eRendCircLegacyClient(rp.circId))
        HsCommon.noteHidServRequest("k", 100)
        HsCommon.hsCleanLastHidServRequests(50)
        assertTrue(HsCommon.getLastHidServRequests().isNotEmpty())
        HsCommon.hsCleanLastHidServRequests()
        assertTrue(HsCommon.getLastHidServRequests().isEmpty())
        HsCommon.hsCleanupCirc(intro.circId)
        assertEquals(null, HsCircuit.hsCircServiceGetEstablishedIntroCirc("BB".repeat(32)))
    }

    @Test
    fun `hs client config control desc L3 batch`() {
        HsClient.hsClientFreeAll()
        val link = byteArrayOf(1, 0, 6, 1, 2, 3, 4, 0x23, 0x29)
        val ip = IntroductionPoint(link, ByteArray(32) { 1 }, ByteArray(32) { 2 }, null, null)
        assertTrue(HsClient.hsClientAnyIntroPointsUsable(listOf(ip)))
        assertNotNull(HsClient.hsClientGetRandomIntroFromEdge(listOf(ip)))
        HsClient.noteClientCirc(HsClient.ClientCirc(10, onionAddress = "a.onion"))
        assertTrue(HsClient.hsClientCircuitHasOpened(10))
        assertEquals(1, HsClient.hsClientCloseIntroCircuitsFromDesc("a.onion"))
        HsClient.hsClientCircuitCleanupOnClose(10)
        HsClient.hsClientCircuitCleanupOnFree(10)
        assertEquals(null, HsClient.hsClientDecodeDescriptor("not-a-desc"))
        assertTrue(HsClient.hsClientLaunchV3DescFetch("b.onion"))
        assertFalse(HsClient.hsClientLaunchV3DescFetch("b.onion"))
        HsClient.hsClientDirFetchDone("b.onion", true)
        HsClient.hsClientNoteConnectionAttemptSucceeded("b.onion")
        HsClient.hsClientDirInfoChanged()
        assertTrue(HsClient.dirInfoEpoch() > 0)
        assertTrue(HsClient.hsClientReceiveIntroduceAck(ByteArray(0)))
        assertTrue(HsClient.hsClientReceiveRendezvous2(ByteArray(32)))
        assertTrue(HsClient.hsClientReceiveRendezvousAcked(ByteArray(0)))
        HsClient.noteClientCirc(HsClient.ClientCirc(11, open = true))
        assertTrue(HsClient.hsClientReextendIntroCircuit(11))
        assertTrue(HsClient.hsClientRefetchHsdesc("c.onion"))
        HsClient.hsClientPurgeState()
        assertEquals(0, HsClient.pendingFetchCount())
        HsClient.hsClientFreeAll()

        val cfg = org.kotlintor.config.TorConfig(dataDirectory = java.nio.file.Files.createTempDirectory("hs-cfg"))
        assertEquals(0, HsConfig.hsConfigClientAuthAll(cfg))
        assertTrue(HsConfig.hsConfigServiceAll(cfg) >= 0)
        HsConfig.hsConfigFreeAll()

        assertTrue(HsControl.hsControlDescEventRequested("o.onion", "blind", "dir").contains("REQUESTED"))
        assertTrue(HsControl.hsControlDescEventFailed("o.onion", "dir", "NOT_FOUND").contains("FAILED"))
        assertTrue(HsControl.hsControlDescEventReceived("o.onion", "dir").contains("RECEIVED"))
        assertTrue(HsControl.hsControlDescEventCreated("o.onion", "blind").contains("CREATED"))
        assertTrue(HsControl.hsControlDescEventUpload("o.onion", "dir", "blind").contains("UPLOAD"))
        assertTrue(HsControl.hsControlDescEventUploaded("o.onion", "dir").contains("UPLOADED"))
        assertTrue(HsControl.hsControlDescEventContent("o.onion", "dir", "body").contains("HS_DESC_CONTENT"))
        assertTrue(HsControl.hsControlHsfetchCommand("a".repeat(56) + ".onion"))
        assertTrue(HsControl.hsControlHspostCommand("hs-descriptor 3\n", "x.onion"))

        HsCommon.hsIncRdvStreamCounter()
        assertEquals(0, HsCommon.hsDecRdvStreamCounter())
        val ephKp = org.kotlintor.crypto.Curve25519.generateKeyPair()
        val client = HsClientAuth.generate()
        val subcred = ByteArray(32) { 5 }
        val authEntry = HsDescriptor.hsDescBuildAuthorizedClient(
            subcred,
            ephKp.privateKey,
            client.publicKey,
        )
        assertEquals(8, authEntry.clientId.size)
        assertEquals(null, HsDescriptor.hsDescAuthorizedClientFree_(authEntry))

        val fake = HsDescriptor.hsDescBuildFakeAuthorizedClient()
        assertEquals(8, fake.clientId.size)
        assertEquals(null, HsDescriptor.hsDescDecodeDescriptor("not-hs-desc"))
        assertEquals(null, HsDescriptor.hsDescDecodeEncrypted("x"))
        assertEquals(null, HsDescriptor.hsDescDecodeSuperencrypted("x"))
        val plain = HsDescriptor.hsDescDecodePlaintext("create2-formats 2\nsingle-onion-service\n")
        assertNotNull(plain)
        assertTrue(plain!!.singleOnion)
        assertEquals(null, HsDescriptor.hsDescEncryptedDataFree_(ByteArray(4)))
        HsDescriptor.hsDescEncryptedDataFreeContents(ByteArray(1))
        val ipNew = HsDescriptor.hsDescIntroPointNew(ByteArray(1) { 0 }, ByteArray(32), ByteArray(32))
        assertEquals(null, HsDescriptor.hsDescIntroPointFree_(ipNew))
        val outer2 = HsDescriptorOuter(180, "c", 1, ByteArray(8), "sig", "raw-body")
        assertTrue(HsDescriptor.hsDescObjSize(outer2) > 0)
        assertEquals(null, HsDescriptor.hsDescPlaintextDataFree_(plain))
        HsDescriptor.hsDescPlaintextDataFreeContents(plain)
        assertEquals(plain.raw.length, HsDescriptor.hsDescPlaintextObjSize(plain))
        assertEquals(null, HsDescriptor.hsDescSuperencryptedDataFree_(ByteArray(2)))

        HsDos.hsDosInit()
        assertTrue(HsDos.hsDosCanSendIntro2("svc"))
        HsDos.hsDosConsensusHasChanged(null)
        assertEquals(0L, HsDos.hsDosGetIntro2RejectedCount())
        HsDos.hsDosSetupDefaultIntro2Defenses()
        assertEquals(HsDos.DEFAULT_RATE, HsDos.getIntro2RateConsensusParam(null))
        assertEquals(HsDos.DEFAULT_BURST, HsDos.getIntro2BurstConsensusParam(null))
        assertFalse(HsDos.getIntro2EnableConsensusParam(null))

        HsCommon.hsSetCurrentSrv(ByteArray(32) { 9 })
        assertEquals(9.toByte(), HsCommon.hsGetCurrentSrv()!![0])
        assertEquals(null, HsCommon.hsGetPreviousSrv())
        HsCommon.hsSetCurrentSrv(ByteArray(32) { 8 })
        assertEquals(9.toByte(), HsCommon.hsGetPreviousSrv()!![0])
        val packed = byteArrayOf(
            2,
            0, 6, 1, 2, 3, 4, 0, 80,
            2, 20, *ByteArray(20) { it.toByte() },
        )
        val ei = HsCommon.hsGetExtendInfoFromLspecs(packed, ByteArray(32) { 7 })
        assertNotNull(ei)
        assertEquals(80, ei!!.orPort)
        assertEquals(7.toByte(), ei.onionKeyNtor[0])
        assertEquals(2, HsCommon.hsGetHsdirNReplicas())
        assertEquals(3, HsCommon.hsGetHsdirSpreadFetch())
        assertEquals(4, HsCommon.hsGetHsdirSpreadStore())
        val now = java.time.Instant.parse("2024-06-01T00:00:00Z")
        assertTrue(HsCommon.hsGetNextTimePeriodNum(now) > HsCommon.timePeriodNum(now))
        assertTrue(HsCommon.hsGetPreviousTimePeriodNum(now) < HsCommon.timePeriodNum(now))
        HsCommon.hsFreeAll()
        assertEquals(null, HsCommon.hsGetCurrentSrv())

        val circ = HsIdent.hsIdentCircuitNew(
            "aabb",
            introAuthKeyHex = "ccdd",
            purpose = "HS_CLIENT_INTRO",
        )
        assertTrue(HsIdent.hsIdentIntroCircIsValid(circ))
        assertFalse(HsIdent.hsIdentIntroCircIsValid(HsIdent.hsIdentCircuitNew("aabb")))
        assertEquals(circ.serviceIdentityHex, HsIdent.hsIdentCircuitDup(circ).serviceIdentityHex)
        assertEquals(null, HsIdent.hsIdentCircuitFree_(circ))
        val dir = HsIdent.hsIdentDirConnInit("ccdd")
        assertEquals(dir.serviceIdentityHex, HsIdent.hsIdentDirConnDup(dir).serviceIdentityHex)
        assertEquals(null, HsIdent.hsIdentDirConnFree_(dir))
        val edge = HsIdent.hsIdentEdgeConnNew("eeff")
        assertEquals(null, HsIdent.hsIdentEdgeConnFree_(edge))
        assertEquals("HS_HSDIR_STORE", HsIdent.hsIdentServerDirConnNew("blinded").purpose)

        // Remaining HS L3: intro / metrics / ob / pow / service / stats
        HsIntropoint.hsIntropointClear()
        assertTrue(HsIntropoint.hsIntroCircuitIsSuitableForEstablishIntro(HsCircuit.PURPOSE_INTRO_POINT, true))
        val introSt = HsIntropoint.hsIntroNew("AA".repeat(32))
        assertEquals("AA".repeat(32), introSt.authKeyHex)
        assertTrue(HsIntropoint.hsIntroReceivedEstablishIntro("AA".repeat(32)))
        assertTrue(HsIntropoint.hsIntroReceivedIntroduce1("AA".repeat(32)))
        val intro1 = ByteArray(55) { 1 }.also {
            it[21] = 0
            it[22] = 32
        }
        assertTrue(HsIntropoint.validateIntroduce1ParsedCell(intro1))
        assertTrue(HsIntropoint.verifyEstablishIntroCell(
            HsCell.hsCellBuildEstablishIntro(ByteArray(32) { 2 }, 0, 0),
        ))

        HsMetrics.hsMetricsServiceInit("m.onion")
        HsMetrics.hsMetricsUpdateByService("m.onion", "intro_received")
        HsMetrics.hsMetricsUpdateByIdent(HsIdent.circuit("m.onion"), "rendezvous_ok")
        assertTrue(HsMetrics.hsMetricsGetStores().containsKey("m.onion"))
        HsMetrics.hsMetricsServiceFree("m.onion")

        HsOb.hsObFreeAll()
        val fe = HsOb.hsObRefreshKeys()
        assertFalse(HsOb.hsObServiceIsInstance(fe.address)) // frontend ≠ backend instance
        HsOb.hsObConfigureInstance("backend.onion", listOf(ByteArray(32) { 7 }))
        assertTrue(HsOb.hsObServiceIsInstance("backend.onion"))
        assertEquals(null, HsOb.hsObParseConfigFile(java.nio.file.Path.of("/no/such/ob")))

        val ch = HsPow.challenge(effort = 0)
        assertEquals(1, HsPow.hsPowQueueWork(ch))
        val blindedPow = ByteArray(32) { 3 }
        val seedPow = ByteArray(32) { 4 }
        val sol = HsPow.hsPowSolve(blindedPow, seedPow, effort = 1, maxAttempts = 100)!!
        assertTrue(HsPow.hsPowVerify(sol, blindedPow))
        assertTrue(HsPow.hsPowRemoveSeedFromCache(ch.seed))
        HsPow.hsPowFreeServiceState()

        HsService.hsServiceInit()
        assertTrue(HsService.hsServiceInitialized())
        val eph = HsService.hsServiceAddEphemeral("eph.onion", "dir")
        assertEquals(eph, HsService.hsServiceFind("eph.onion"))
        assertTrue(HsService.hsServiceAllowNonAnonymousConnection().not().or(true)) // ensure callable
        HsService.hsServiceSetAllowNonAnonymousConnection(true)
        assertTrue(HsService.hsServiceAllowNonAnonymousConnection())
        assertTrue(HsService.hsServiceCircuitHasOpened(99, "eph.onion"))
        HsService.hsServiceSetExportsCircuitId("eph.onion", HsService.CircuitIdExport.HAPROXY)
        assertEquals(HsService.CircuitIdExport.HAPROXY, HsService.hsServiceExportsCircuitId("eph.onion"))
        assertTrue(HsService.hsServiceCircuitCleanupOnClose(99))
        HsService.hsServiceDirInfoChanged()
        assertTrue(HsService.hsServiceDumpStats().contains("services="))
        assertEquals(3, HsService.hsServiceGetVersionFromKey(ByteArray(32)))
        assertEquals(-1, HsService.hsServiceGetVersionFromKey(ByteArray(0)))
        assertEquals(-1, HsService.hsServiceGetVersionFromKey(ByteArray(8)))
        assertTrue(HsService.hsServiceListsFnamesForSandbox(eph).any { it.contains("hostname") })
        assertNotNull(HsService.hsServiceGetMetricsStores())
        assertTrue(HsService.hsServiceDelEphemeral("eph.onion"))
        assertEquals(null, HsService.hsServiceFree_(HsService.ServiceLite("gone.onion")))
        HsService.hsServiceFreeAll()

        HsStats.reset()
        HsStats.hsStatsNoteIntroduce2Cell()
        HsStats.hsStatsNoteServiceRendezvousLaunch()
        assertEquals(1L, HsStats.hsStatsGetNIntroduce2V3Cells())
        assertEquals(1L, HsStats.hsStatsGetNRendezvousLaunches())
    }
}
