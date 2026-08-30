package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.AuthMode
import org.kotlintor.dir.AuthModeOptions
import org.kotlintor.dir.BandwidthVote
import org.kotlintor.dir.BridgeAuth
import org.kotlintor.dir.BwAuth
import org.kotlintor.dir.ConsCache
import org.kotlintor.dir.ConsDiff
import org.kotlintor.dir.ConsDiffMgr
import org.kotlintor.dir.DirAuthConfig
import org.kotlintor.dir.DirAuthOptions
import org.kotlintor.dir.DirAuthPeriodic
import org.kotlintor.dir.DirAuthSys
import org.kotlintor.dir.DirClientModes
import org.kotlintor.dir.DirCollate
import org.kotlintor.dir.DirVote
import org.kotlintor.dir.DirVoteActor
import org.kotlintor.dir.Directory
import org.kotlintor.dir.DsigsParse
import org.kotlintor.dir.FpPair
import org.kotlintor.dir.GuardFraction
import org.kotlintor.dir.Keypin
import org.kotlintor.dir.ProcessDescs
import org.kotlintor.dir.Reachability
import org.kotlintor.dir.ReachabilityTracker
import org.kotlintor.dir.RecommendPkg
import org.kotlintor.dir.SharedRandom
import org.kotlintor.dir.SharedRandomState
import org.kotlintor.dir.VoteFlags
import org.kotlintor.dir.VotingSchedule
import java.nio.file.Files

/**
 * Elevates dirauth / dircache / dirclient / dircommon L1 units to D3.
 */
class DirAuthElevationTest {
    @Test
    fun `dirauth config sys periodic`() {
        val dir = Files.createTempDirectory("ktor-da")
        val cfg = TorrcParser.parse(
            "AuthoritativeDirectory 1\nV3AuthoritativeDirectory 1\nORPort 9001\n",
            dir,
        )
        assertTrue(DirAuthConfig.enabled(cfg))
        DirAuthSys.init(cfg)
        assertNotNull(DirAuthPeriodic.scheduleHints(cfg)["vote_interval_sec"])
        DirAuthSys.shutdown()
        assertFalse(DirAuthSys.isStarted())
        assertTrue(DirClientModes.directoryFetchesV3(cfg))
        assertEquals("fetch_consensus", Directory.PURPOSE_FETCH_CONSENSUS)
        assertTrue(DirVote.MIN_VOTE_INTERVAL > 0)
    }

    @Test
    fun `bridgeauth bwauth process_descs recommend`() {
        val body = BridgeAuth.formatNetworkstatusBridges(
            listOf(
                BridgeAuth.BridgeStatus(
                    identityHex = "A".repeat(40),
                    nickname = "br1",
                    ip = "127.0.0.1",
                    orPort = 9001,
                    flags = setOf("Running", "Valid"),
                ),
            ),
        )
        assertTrue(body.contains("published"))
        val bw = BwAuth.parse("node_id=${"B".repeat(40)} bw=100\n")
        assertEquals(1, bw.lines.size)
        val pd = ProcessDescs()
        pd.addRsaFingerprint("C".repeat(40), ProcessDescs.RTR_REJECT)
        assertTrue(pd.wouldReject("C".repeat(40)))
        assertTrue(RecommendPkg.validate("tor 0.4.8.0 https://example.com sha256=abcd"))
        assertTrue(AuthMode.isAuthority(AuthModeOptions(authoring = true)))
    }

    @Test
    fun `process_descs shared_random L3 aliases`() {
        ProcessDescs.dirservFreeFingerprintList()
        val list = ProcessDescs.authdirInitFingerprintList()
        assertNotNull(ProcessDescs.authdirReturnFingerprintList())
        assertEquals(0, ProcessDescs.addRsaFingerprintToDir("A".repeat(40), ProcessDescs.RTR_REJECT))
        assertEquals(0, ProcessDescs.addEd25519ToDir("B".repeat(64), ProcessDescs.RTR_BADEXIT))
        assertEquals(1 to false, list.authdirWantsToRejectRouter("A".repeat(40), complain = true))
        assertEquals(1, list.dirservWouldRejectRouter("A".repeat(40)))
        assertEquals(0, list.addRsaFingerprintToDir("D".repeat(40), 0))
        val (added, _) = list.dirservAddDescriptor(
            ProcessDescs.Descriptor(nickname = "n1", identityHex = "D".repeat(40), body = "x"),
        )
        assertEquals(ProcessDescs.Added.ADDED, added)

        val id = ByteArray(20) { 1 }
        val c = SharedRandom.generateCommit(id)
        assertTrue(SharedRandom.commitDecode(c.encodedCommit, c.encodedReveal))
        assertEquals(c.encodedCommit, SharedRandom.commitEncode(c))
        assertTrue(SharedRandom.commitHasRevealValue(c))
        assertTrue(SharedRandom.commitIsAuthoritative(c))
        assertTrue(SharedRandom.commitmentsAreTheSame(c, c))
    }

    @Test
    fun `dirauth vote bridge collate sched L3 batch`() {
        assertEquals("CERT", DirVote.authorityCertDup("CERT"))
        val a = DirVote.RouterInfoLite("AA".repeat(20), ipv4 = "1.2.3.4", orPort = 9001, bandwidthKb = 100)
        val b = DirVote.RouterInfoLite("BB".repeat(20), ipv4 = "2.3.4.5", orPort = 9001, bandwidthKb = 50)
        assertTrue(DirVote.compareRouterinfoByIpv4(a, b) < 0)
        assertTrue(DirVote.compareRouterinfoByIpv6(a.copy(ipv6 = "::1"), b.copy(ipv6 = "::2")) < 0)
        assertTrue(DirVote.compareRouterinfoUsefulness(a, b) > 0)
        assertTrue(DirVote.computeConsensusPackageLines(listOf("tor 0.4.8.0 https://x sha256=ab")).contains("package"))

        val dir = Files.createTempDirectory("ktor-ba")
        val out = BridgeAuth.bridgeauthDumpBridgeStatusToFile(
            dir,
            listOf(BridgeAuth.BridgeStatus("A".repeat(40), "br", "127.0.0.1", 9001, setOf("Running"))),
        )
        assertTrue(Files.exists(out))

        assertEquals(0, DirAuthSys.dirauthSetOptions(DirAuthOptions(authoritativeDirectory = true, votingIntervalSec = 300)))
        assertTrue(DirAuthSys.dirauthGetOptions().authoritativeDirectory)
        assertEquals(0, DirAuthPeriodic.dirauthRegisterPeriodicEvents())
        assertTrue(DirAuthPeriodic.isRegistered())

        val sched = VotingSchedule.dirauthSchedRecalculateTiming(1_700_000_000L, intervalSec = 300)
        assertEquals(300, VotingSchedule.dirauthSchedGetConfiguredInterval())
        assertEquals(sched.intervalStartsEpochSec, VotingSchedule.dirauthSchedGetCurValidAfterTime())
        assertTrue(VotingSchedule.dirauthSchedGetNextValidAfterTime(1_700_000_000L) > 0)

        val rs = VoteFlags.dirauthSetRouterstatusFromRouterinfo(
            "E".repeat(40),
            "nick",
            VoteFlags.Input(isRunning = true, isValid = true, bandwidthKb = 5000, weightedBwKb = 5000),
        )
        assertTrue(rs.flags.contains("Running"))
        assertNotNull(VoteFlags.dirservComputePerformanceThresholds())
        assertNotNull(VoteFlags.dirservComputeBridgeFlagThresholds())

        DirAuthConfig.setRejectRequestsUnderLoad(true)
        assertTrue(DirAuthConfig.dirauthShouldRejectRequestsUnderLoad())
        DirAuthConfig.setRejectRequestsUnderLoad(false)

        val emptyHeader = BandwidthVote.VoteHeader(
            networkStatusVersion = 3,
            voteStatus = "vote",
            published = null,
            validAfter = null,
            freshUntil = null,
            validUntil = null,
            votingDelay = null,
            knownFlags = emptyList(),
            params = emptyMap(),
        )
        val vote = BandwidthVote.VoteDocument(
            emptyHeader,
            listOf(BandwidthVote.RouterBandwidth("n", "FF".repeat(20), bandwidth = 100, measured = 100)),
            raw = "",
        )
        val dc = DirCollate.dircollatorNew(1, 1)
        DirCollate.dircollatorAddVote(dc, vote)
        DirCollate.dircollatorCollate(dc)
        assertEquals(1, DirCollate.dircollatorNRouters(dc))
        assertEquals(1, DirCollate.dircollatorGetVotesForRouter(dc, "FF".repeat(20)).size)
        assertEquals(null, DirCollate.dircollatorFree_(dc))

        val pd = ProcessDescs()
        assertEquals(1, pd.dirservAddMultipleDescriptors("relay1 ${"11".repeat(20)}\n"))
        assertEquals(0, pd.dirservAddOwnFingerprint("22".repeat(20), "33".repeat(32)))

        BwAuth.dirservClearMeasuredBwCache()
        BwAuth.dirservCacheMeasuredBw("44".repeat(20), 999)
        assertEquals(1, BwAuth.dirservCountMeasuredBws())
        BwAuth.dirservExpireMeasuredBwCache()
        assertEquals(999L, BwAuth.measuredBw("44".repeat(20)))
    }

    @Test
    fun `dirauth dirserv reachability vote L3 batch`() {
        ProcessDescs.dirservFreeFingerprintList()
        ProcessDescs.authdirInitFingerprintList()
        val pd = ProcessDescs.authdirReturnFingerprintList()!!
        assertEquals(1, pd.dirservLoadFingerprintFile("!reject ${"AA".repeat(20)}\n"))
        assertEquals(1, pd.dirservWouldRejectRouter("AA".repeat(20)))
        assertTrue(pd.dirservRejectsTorVersion("0.4.7.0", "0.4.8.0"))
        assertFalse(pd.dirservRejectsTorVersion("0.4.9.0", "0.4.8.0"))
        assertEquals(ProcessDescs.RTR_REJECT, pd.dirservRouterGetStatus("AA".repeat(20)))
        pd.dirservSetNodeFlagsFromAuthoritativeStatus("BB".repeat(20), ProcessDescs.RTR_BADEXIT)
        assertEquals(ProcessDescs.RTR_BADEXIT, pd.dirservRouterGetStatus("BB".repeat(20)))
        assertTrue(
            pd.dirservRouterHasValidAddress(
                ProcessDescs.Descriptor("n", "CC".repeat(20), ip = "1.2.3.4", orPort = 9001),
            ),
        )
        assertFalse(
            pd.dirservRouterHasValidAddress(
                ProcessDescs.Descriptor("n", "CC".repeat(20), ip = "0.0.0.0", orPort = 9001),
            ),
        )
        ProcessDescs.dirservFreeFingerprintList()

        BwAuth.dirservClearMeasuredBwCache()
        val n = BwAuth.dirservReadMeasuredBandwidths("node_id=${"DD".repeat(20)} bw=500\n")
        assertEquals(1, n)
        assertTrue(BwAuth.dirservHasMeasuredBw("DD".repeat(20)))
        assertEquals(1, BwAuth.dirservGetMeasuredBwCacheSize())
        assertEquals(500L, BwAuth.dirservQueryMeasuredBwCacheKb("DD".repeat(20)))
        assertEquals(1, BwAuth.dirservGetLastNMeasuredBws())
        assertEquals(500L, BwAuth.dirservGetCredibleBandwidthKb("DD".repeat(20), 100))
        assertEquals(100L, BwAuth.dirservGetCredibleBandwidthKb("EE".repeat(20), 100))

        val line = VoteFlags.dirservGetFlagThresholdsLine()
        assertTrue(line.contains("fast-speed="))
        VoteFlags.dirservSetRouterIsRunning("FF".repeat(20), true)
        assertTrue(VoteFlags.isRouterRunning("FF".repeat(20)))
        VoteFlags.dirservSetBridgesRunning(true)
        assertTrue(VoteFlags.bridgesAreRunning())
        val testing = VoteFlags.dirservSetRouterstatusTesting("11".repeat(20), "TestNick")
        assertTrue(testing.flags.contains("Running"))

        val gfText =
            "guardfraction-file-version 1\nwritten-at 2020-01-01 00:00:00\nn-inputs 1 1\n" +
                "guard-seen ${"ab".repeat(20)} 50 1\n"
        val pct = LinkedHashMap<String, Int>()
        assertEquals(1, GuardFraction.dirservReadGuardfractionFileFromStr(gfText, pct))
        assertEquals(50, pct["ab".repeat(20)])
        assertEquals(1, GuardFraction.dirservReadGuardfractionFile(gfText, LinkedHashMap()))

        val tracker = Reachability.tracker()
        val t = ReachabilityTracker.Target("22".repeat(20), "9.9.9.9", 9001)
        tracker.noteTarget(t)
        assertTrue(Reachability.dirservShouldLaunchReachabilityTest(t, null, tracker))
        assertTrue(Reachability.dirservOrconnTlsDone("22".repeat(20), "9.9.9.9", 9001, tracker = tracker))
        assertTrue(Reachability.dirservSingleReachabilityTest(t, tracker))
        assertTrue(Reachability.dirservTestReachability(tracker) >= 0)

        val voteBody = DirVote.dirservGenerateNetworkstatusVoteObj(
            listOf(DirVote.RouterInfoLite("33".repeat(20), ipv4 = "1.1.1.1", orPort = 9001, bandwidthKb = 10)),
        )
        assertTrue(voteBody.contains("vote-status vote"))
        val timing = DirVote.Timing(voteIntervalSec = 300, voteSeconds = 50, distSeconds = 50)
        val sched = DirVote.buildSchedule(timing, 1_700_000_300L)
        val actor = DirVoteActor(timing, sched)
        assertTrue(DirVote.dirvoteAct(actor, sched.votingStarts) >= 0)
        DirVote.dirvoteAddVote(actor, voteBody)
        assertTrue(DirVote.dirvoteAddSignatures(voteBody, "directory-signature 00 aa").contains("directory-signature"))
        DirVote.dirvoteNoteCommit("44".repeat(20), "shared-rand-commit 1")
        assertEquals(1, DirVote.dirvotePendingCommitCount())
        DirVote.dirvoteClearCommits()
        assertEquals(0, DirVote.dirvotePendingCommitCount())
        val params = DirVote.dirvoteComputeParams(
            listOf(mapOf("bwweightscale" to 10000), mapOf("bwweightscale" to 10000)),
        )
        assertEquals(10000, params["bwweightscale"])
        assertTrue(DirVote.dirvoteCreateMicrodescriptor("-----BEGIN RSA PUBLIC KEY-----\nM\n-----END RSA PUBLIC KEY-----").contains("onion-key"))
    }

    @Test
    fun `dirauth keypin sr vote format L3 batch`() {
        Keypin.keypinCloseJournal()
        val j = Keypin.keypinOpenJournal()
        val rsa = ByteArray(20) { 1 }
        val ed = ByteArray(32) { 2 }
        assertEquals(Keypin.Result.NOT_FOUND, Keypin.keypinCheck(rsa, ed))
        assertEquals(Keypin.Result.ADDED, Keypin.keypinCheckAndAdd(rsa, ed))
        assertEquals(Keypin.Result.FOUND, Keypin.keypinCheck(rsa, ed))
        assertEquals(Keypin.Result.MISMATCH, Keypin.keypinCheckLoneRsa(rsa))
        assertTrue(Keypin.keypinParseJournalLine("rsa-ed ${"aa".repeat(20)} ${"bb".repeat(32)}"))
        Keypin.keypinLoadJournal("rsa-ed ${"cc".repeat(20)} ${"dd".repeat(32)}\n")
        Keypin.keypinLoadJournalImpl("rsa-ed ${"ee".repeat(20)} ${"ff".repeat(32)}\n")
        Keypin.keypinClear()
        Keypin.keypinCloseJournal()
        assertEquals(null, Keypin.keypinActiveJournal())

        val path = Files.createTempDirectory("sr2").resolve("sr_state")
        SharedRandomState.newProtocolRun(1_800_000_000L)
        assertEquals("commit", SharedRandomState.getPhaseStr())
        assertEquals(SharedRandom.Phase.COMMIT, SharedRandomState.getSrProtocolPhase())
        assertTrue(SharedRandomState.srStateIsInitialized())
        SharedRandomState.setStateValidUntilTime(1_800_000_000L)
        assertEquals(1_800_000_000L, SharedRandomState.getStateValidUntilTime())
        assertTrue(SharedRandomState.isPhaseTransition(1_800_000_100L, 1_800_000_050L))
        assertEquals(SharedRandom.Phase.REVEAL, SharedRandomState.getSrProtocolPhase())
        SharedRandomState.getSrState().state.save(path)
        SharedRandomState.diskStateLoadFromDiskImpl(path)
        SharedRandomState.resetStateForNewProtocolRun(1_900_000_000L)

        val id = ByteArray(20) { 3 }
        val c = SharedRandom.generateCommit(id)
        val encReveal = SharedRandom.revealEncode(c.revealTs, c.randomNumber)
        assertNotNull(SharedRandom.revealDecode(encReveal))
        SharedRandom.setNumSrvAgreements(3)
        assertEquals(3, SharedRandom.getNumSrvAgreements())
        val st = SharedRandom.State()
        SharedRandom.saveCommitToState(st, c)
        assertTrue(SharedRandom.saveCommitDuringRevealPhase(st, c))
        val srv = SharedRandom.computeSrv(listOf(c))
        assertNotNull(SharedRandom.getMajoritySrvFromVotes(listOf(srv, srv)))

        val timing = DirVote.Timing(300, 50, 50)
        val actor = DirVoteActor(timing, DirVote.buildSchedule(timing, 1_700_000_300L))
        val vote = DirVote.formatNetworkstatusVote(
            listOf(DirVote.RouterInfoLite("55".repeat(20), ipv4 = "10.0.0.1", orPort = 9001)),
        )
        DirVote.dirvoteAddVote(actor, vote)
        assertNotNull(DirVote.dirvoteGetVote(actor, "55"))
        assertTrue(DirVote.dirvoteDirreqGetStatusVote(actor).isNotEmpty())
        assertTrue(DirVote.dirvoteFormatAllMicrodescVoteLines(listOf("onion-key\n")).startsWith("m "))
        assertEquals(10000, DirVote.dirvoteGetIntermediateParamValue(listOf(mapOf("x" to 10000)), "x"))
        assertTrue(DirVote.formatRecommendedVersionList(listOf("0.4.8.0")).contains("recommended"))
        assertTrue(DirVote.makeConsensusMethodList().contains("32"))
        assertTrue(DirVote.networkstatusComputeBwWeightsV10().contains("Wgg="))
        val syb = DirVote.getAllPossibleSybil(
            listOf(
                DirVote.RouterInfoLite("61".repeat(20), ipv4 = "1.1.1.1"),
                DirVote.RouterInfoLite("62".repeat(20), ipv4 = "1.1.1.1"),
                DirVote.RouterInfoLite("63".repeat(20), ipv4 = "1.1.1.1"),
            ),
            maxPerAddr = 2,
        )
        assertEquals(1, syb.size)
        assertTrue(DirVote.getSybilListByIpVersion(emptyList(), ipv6 = true).isEmpty())
        val detached = DsigsParse.networkstatusParseDetachedSignatures(
            "consensus-digest AAAA\n",
        )
        assertEquals(null, DsigsParse.nsDetachedSignaturesFree_(detached))
        assertTrue(
            DirVote.networkstatusAddDetachedSignatures("network-status-version 3\n", detached)
                .contains("network-status-version"),
        )
        DirVote.dirvoteFreeAll(actor)
        assertTrue(actor.pendingVotes().isEmpty())

        val opts = DirAuthOptions(authoritativeDirectory = true, votingIntervalSec = 300, voteDelaySec = 20, distDelaySec = 20)
        assertEquals(0, DirAuthConfig.optionsActDirauth(opts))
        assertEquals(0, DirAuthConfig.optionsActDirauthMtbf(opts))
        assertEquals(0, DirAuthConfig.optionsActDirauthStats(opts))
        assertTrue(DirAuthConfig.optionsValidateDirauthMode(opts).isEmpty())
        assertTrue(DirAuthConfig.optionsValidateDirauthSchedule(opts).isEmpty())
        assertTrue(DirAuthConfig.optionsValidateDirauthTesting(opts).isEmpty())
        assertEquals(0, DirAuthPeriodic.rescheduleDirvote())
        assertTrue(VoteFlags.runningLongEnoughToDecideUnreachable(10_000))
        val line = BwAuth.measuredBwLineParse("node_id=${"66".repeat(20)} bw=42")
        assertNotNull(line)
        BwAuth.measuredBwLineApply(line!!)
        assertEquals(42L, BwAuth.measuredBw("66".repeat(20)))

        val commitLine = c.voteLine(SharedRandom.Phase.REVEAL)
        assertTrue(DirVote.dirvoteParseSrCommits(commitLine).isNotEmpty())
    }

    @Test
    fun `dirauth sr state finish L3 batch`() {
        SharedRandomState.srStateFreeAll()
        val ps = SharedRandomState.srStateInit()
        assertTrue(SharedRandomState.srStateIsInitialized(ps))
        SharedRandomState.setSrPhase(SharedRandom.Phase.REVEAL, ps)
        assertEquals(SharedRandom.Phase.REVEAL, SharedRandomState.srStateGetPhase(ps))

        val id = ByteArray(20) { 7 }
        val c = SharedRandom.srGenerateOurCommit(id)
        assertTrue(SharedRandom.shouldKeepCommit(c))
        assertTrue(SharedRandom.verifyCommitAndReveal(c))
        assertEquals(null, SharedRandom.srCommitFree_(c))
        assertNotNull(SharedRandom.srParseCommit(c.voteLine(SharedRandom.Phase.REVEAL)))
        SharedRandomState.srStateAddCommit(c, ps)
        assertNotNull(SharedRandomState.srStateGetCommit(c.rsaIdentityHex, ps))
        assertEquals(1, SharedRandomState.srStateGetCommits(ps).size)
        assertTrue(SharedRandomState.srStateCopyRevealInfo(c, c.rsaIdentityHex, ps))

        val srv = SharedRandom.srComputeSrv(listOf(c))
        val dup = SharedRandom.srSrvDup(srv)
        assertEquals(srv.encodeBase64(), dup.encodeBase64())
        SharedRandomState.srStateSetCurrentSrv(srv, ps)
        SharedRandomState.srStateSetPreviousSrv(null, ps)
        SharedRandomState.srStateSetFreshSrv(true, ps)
        assertNotNull(SharedRandomState.srStateGetCurrentSrv(ps))
        assertEquals(null, SharedRandomState.srStateGetPreviousSrv(ps))
        assertTrue(SharedRandom.srGetStringForConsensus(srv).contains("shared-rand-current-value"))
        assertTrue(SharedRandom.srGetStringForVote(c, SharedRandom.Phase.COMMIT).contains(SharedRandom.COMMIT_NS))
        assertEquals(1, SharedRandom.srHandleReceivedCommits(ps.state, listOf(c)))
        SharedRandom.srActPostConsensus(ps.state)
        SharedRandomState.srStateSetFreshSrv(false, ps)
        SharedRandomState.srStateCleanSrvs(ps)
        SharedRandomState.srStateDeleteCommits(ps)
        assertTrue(SharedRandomState.srStateGetCommits(ps).isEmpty())

        val st = SharedRandom.srInit()
        st.put(c)
        val path = Files.createTempDirectory("sr3").resolve("st")
        SharedRandom.srSaveAndCleanup(st, path)
        assertTrue(Files.exists(path))
        SharedRandomState.srStateSave(path, ps)
        assertTrue(RecommendPkg.validateRecommendedPackageLine("tor 0.4.8.0 https://x sha256=ab"))
    }

    @Test
    fun `conscache consdiff collate vote flags fp`() {
        val cache = ConsCache()
        val e = cache.put("network-status-version 3\n")
        assertEquals(64, e.digestHex.length)
        val d = ConsDiff.generate("a\n", "b\n")
        assertTrue(ConsDiff.looksLikeDiff(d))
        val mgr = ConsDiffMgr(cache)
        mgr.storeDiff("old\n", "new\n")
        assertTrue(mgr.size() >= 1)
        assertTrue(DirCollate.collate(emptyList()).isEmpty())
        val flags = VoteFlags.assign(VoteFlags.Input(isRunning = true, isValid = true, bandwidthKb = 1000))
        assertTrue(flags.isNotEmpty())
        val fp = FpPair.of(ByteArray(20) { 1 }, ByteArray(32) { 2 })
        assertEquals(40, fp.rsaIdHex.length)
        assertEquals(64, DsigsParse.digestHex("body").length)
    }

    @Test
    fun `guardfraction reachability shared random`() {
        val gf = GuardFraction.parse("guardfraction-file-version 1\n")
        assertNotNull(gf)
        val tracker = Reachability.tracker()
        val t = ReachabilityTracker.Target("D".repeat(40), "1.2.3.4", 9001)
        assertTrue(Reachability.shouldLaunchTest(tracker, t, null))
        val state = SharedRandom.State()
        val path = Files.createTempDirectory("sr").resolve("sr_state")
        SharedRandomState.save(state, path)
        SharedRandomState.load(state, path)
        assertTrue(path.toFile().exists())
    }
}
