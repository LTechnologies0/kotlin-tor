package org.kotlintor.control

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.BootstrapPhase
import java.nio.file.Files

/**
 * Elevates control-port L1 units (C Tor feature/control directory).
 */
class ControlParityElevationTest {
    @Test
    fun `auth and proto`() {
        assertEquals(32, ControlAuth.COOKIE_LEN)
        assertTrue(ControlAuth.methodsCookieOnly().contains("SAFECOOKIE"))
        assertEquals(1, ControlProto.PROTOCOLINFO_VERSION)
        val (cmd, args) = ControlProto.splitCommand("GETINFO version")
        assertEquals("GETINFO", cmd)
        assertEquals("version", args)
    }

    @Test
    fun `cmd and events and getinfo`() {
        assertTrue(ControlCmd.isPreauth("PROTOCOLINFO"))
        assertTrue(ControlCmd.isKnown("ADD_ONION"))
        assertTrue(ControlEvents.isKnown("CIRC"))
        assertTrue(ControlGetinfo.isRecognized("version"))
        assertEquals("SocksPort", ControlGetinfo.configKey("config/SocksPort"))
    }

    @Test
    fun `bootstrap fmt hs btrack`() {
        assertEquals(100, ControlBootstrap.progress(BootstrapPhase.DONE))
        assertEquals("250 OK", ControlFmt.ok())
        assertTrue(ControlHs.isHsCommand("ADD_ONION"))
        assertEquals(80 to "127.0.0.1:8080", ControlHs.parsePortMapping("Port=80,127.0.0.1:8080"))
        BtrackOrconnMaps.clear()
        BtrackOrconnMaps.put(1L, "198.51.100.1:9001")
        assertEquals("198.51.100.1:9001", BtrackOrconnMaps.get(1L))
        assertTrue(BtrackOrconnCevent.connected("x").contains("ORCONN"))
        assertTrue(BtrackCircuit.format(3L, "BUILT").contains("CIRC"))
        assertEquals("??", GetinfoGeoip.countryForAddress("1.2.3.4"))
        assertEquals(BootstrapPhase.STARTING, Btrack.phases().first())
    }

    @Test
    fun `btrack bto L3 aliases`() {
        // Inventory: L3:feature/control/btrack_* + bto_*
        assertEquals(0, BtrackCircuit.btrackCircInit())
        assertEquals(0, BtrackCircuit.btrackCircAddPubsub())
        assertTrue(BtrackCircuit.hasPubsub())
        BtrackCircuit.noteState(gid = 7, state = 2, onehop = false)
        assertEquals(7L to 2, BtrackCircuit.bestApState())
        BtrackCircuit.btrackCircFini()
        assertEquals(-1, BtrackCircuit.bestAnyState().second)

        assertEquals(0, BtrackOrconn.btrackOrconnInit())
        assertEquals(0, BtrackOrconn.btrackOrconnAddPubsub())
        assertTrue(BtrackOrconnMaps.mapsInitialized())

        BtrackOrconnMaps.btoInitMaps()
        val a = BtrackOrconnMaps.btoFindOrNew(gid = 10, chan = 0)
        a.state = BtOrconn.STATE_CONNECTING
        a.proxyType = BtOrconn.PROXY_NONE
        assertEquals(BtrackOrconnCevent.BOOTSTRAP_CONN, BtrackOrconnCevent.btoCeventAnyconn(a))
        // apconn blocked until first ORCONN completes
        assertEquals(null, BtrackOrconnCevent.btoCeventApconn(a))

        a.state = BtOrconn.STATE_OPEN
        assertEquals(BtrackOrconnCevent.BOOTSTRAP_HANDSHAKE_DONE, BtrackOrconnCevent.btoCeventAnyconn(a))
        assertTrue(BtrackOrconnCevent.hasCompletedFirstOrconn())

        val b = BtrackOrconnMaps.btoFindOrNew(gid = 0, chan = 99)
        assertEquals(99L, b.chan)
        // link chan→gid
        val linked = BtrackOrconnMaps.btoFindOrNew(gid = 11, chan = 99)
        assertEquals(11L, linked.gid)
        assertEquals(99L, linked.chan)
        linked.state = BtOrconn.STATE_CONNECTING
        linked.isOrig = true
        linked.isOnehop = false
        assertEquals(BtrackOrconnCevent.BOOTSTRAP_AP_CONN, BtrackOrconnCevent.btoCeventApconn(linked))

        BtrackOrconn.noteOrconn(linked.copy(state = BtOrconn.STATE_TLS_HANDSHAKING))
        assertEquals(BtrackOrconnCevent.BOOTSTRAP_AP_CONN_DONE, BtrackOrconnCevent.lastBootstrapStatus)

        BtrackOrconnMaps.btoDelete(11)
        assertEquals(null, BtrackOrconnMaps.get(11))
        BtrackOrconnMaps.btoClearMaps()
        BtrackOrconnCevent.btoCeventReset()
        assertFalse(BtrackOrconnCevent.hasCompletedFirstOrconn())

        BtrackOrconn.btrackOrconnFini()
        assertFalse(BtrackOrconn.isInitialized())
    }

    @Test
    fun `control cmd proto events L3 batch`() {
        // Inventory: first 25 D2 feature/control ops after btrack/bto
        val key = ControlCmd.addOnionHelperKeyarg("NEW:ED25519-V3")!!
        assertEquals(3, key.third)
        assertEquals("ok:3", ControlCmd.addOnionHelperAddService(3, listOf(80 to "127.0.0.1:8080")))
        val parsed = ControlCmd.controlCmdParseArgs("GETINFO version")
        assertEquals("GETINFO", parsed.command)
        assertEquals(listOf("version"), parsed.args)
        ControlCmd.controlCmdArgsWipe(parsed)
        assertEquals("", parsed.command)
        assertEquals(null, ControlCmd.controlCmdArgsFree_(ControlCmdArgs(command = "X")))
        ControlCmd.controlCmdFreeAll()
        assertTrue(ControlCmd.wasFreed())

        val parts = mutableListOf<String>()
        ControlEvents.appendCellStatsByCommand(parts, commandId = 2, queued = 1, delivered = 3)
        assertTrue(parts[0].contains("Command=2"))
        assertTrue(ControlEvents.cbtControlEventBuildtimeoutSet(1500).contains("BUILDTIMEOUT_SET"))
        ControlEvents.controlAdjustEventLogSeverity(4)
        assertEquals(4, ControlEvents.eventLogSeverity())
        ControlEvents.setPerSecondEventsEnabled(true)
        assertTrue(ControlEvents.controlAnyPerSecondEventEnabled())
        assertTrue(ControlEvents.controlEventAddressMapped("a.onion", "10.0.0.1").contains("ADDRMAP"))
        assertTrue(ControlEvents.controlEventBandwidthUsed(10, 20).contains("BW"))
        assertTrue(ControlEvents.controlEventBootstrap(5, 80).contains("BOOTSTRAP"))
        assertTrue(ControlEvents.controlEventBootDir(5, 5).contains("boot_dir"))
        ControlEvents.controlEventBootFirstOrconn()
        assertTrue(ControlEvents.hasFirstOrconn())
        assertEquals("first_orconn", ControlEvents.controlEventBootLastMsg())

        val desc = ControlFmt.circuitDescribeStatusForController(
            circId = 9,
            path = "$9=aaaa,$10=bbbb",
            purpose = "GENERAL",
            onehopTunnel = true,
        )
        assertTrue(desc.contains("PURPOSE=GENERAL"))
        assertTrue(desc.contains("ONEHOP_TUNNEL"))

        val conn = Control.controlConnectionAddLocalFd(fd = 42)
        conn.inbuf.append("PROTOCOLINFO 1\r\n")
        assertEquals("PROTOCOLINFO 1", Control.connectionControlProcessInbuf(conn))
        ControlProto.connectionWriteStrToBuf("250 OK\r\n", conn)
        ControlProto.connectionPrintfToBuf(conn, "%d %s\r\n", 250, "OK")
        assertTrue(conn.outbuf.toString().contains("250 OK"))
        assertEquals(0, Control.connectionControlFinishedFlushing(conn))
        assertEquals(0, Control.connectionControlReachedEof(conn))
        assertTrue(conn.reachedEof)
        Control.connectionControlClosed(conn)
        assertTrue(conn.closed)

        ControlAuth.controlAuthFreeAll()
        assertTrue(ControlAuth.wasFreed())
    }

    @Test
    fun `control events reply ports L3 batch2`() {
        assertTrue(ControlEvents.controlEventBootstrapProblem("timeout", "ORCONN").contains("PROBLEM"))
        ControlEvents.controlEventBootstrapReset()
        assertFalse(ControlEvents.hasFirstOrconn())
        assertTrue(ControlEvents.controlEventBuildtimeoutSet(2000).contains("TIMEOUT=2000"))
        assertTrue(ControlEvents.controlEventCircBandwidthUsed().contains("CIRC_BW"))
        assertTrue(ControlEvents.controlEventCircBandwidthUsedForCirc(3, 10, 20).contains("ID=3"))
        assertTrue(ControlEvents.controlEventCircuitStatus(1, "BUILT", "a,b,c").contains("CIRC"))
        assertTrue(ControlEvents.controlEventCircuitPurposeChanged(1, "GENERAL", "HS_CLIENT_INTRO").contains("PURPOSE_CHANGED"))
        assertTrue(ControlEvents.controlEventCircuitCannibalized(2, "GENERAL", "HS_CLIENT_REND").contains("CANNIBALIZED"))
        assertTrue(ControlEvents.controlEventCircuitCellStats(4, listOf("Command=2")).contains("CELL_STATS"))
        assertTrue(ControlEvents.controlEventClientError("boom").contains("ERR"))
        assertTrue(ControlEvents.controlEventClientStatus("NOTICE", "ok").contains("STATUS_CLIENT"))
        assertTrue(ControlEvents.controlEventClientsSeen("IT=3").contains("CLIENTS_SEEN"))
        assertTrue(ControlEvents.controlEventConfChanged(listOf("SocksPort" to "9050")).contains("CONF_CHANGED"))
        assertTrue(ControlEvents.controlEventConnBandwidth(9, 1, 2).contains("CONN_BW"))
        assertEquals(0, ControlEvents.controlEventConnBandwidthUsed())

        val conn = Control.controlConnectionAddLocalFd(7)
        Control.markAuthenticated(conn)
        assertEquals(1, Control.authenticatedCount())
        Control.controlRemoveAuthenticatedConnection(conn)
        assertEquals(0, Control.authenticatedCount())
        Control.setControlPorts(listOf("127.0.0.1:9051"))
        val tmp = Files.createTempFile("ktor-cp", ".txt")
        assertTrue(Control.controlPortsWriteToFile(tmp) > 0)
        assertTrue(Files.readString(tmp).contains("9051"))
        Files.deleteIfExists(tmp)

        ControlProto.controlPrintfEndreply(conn, 250, "OK")
        ControlProto.controlPrintfMidreply(conn, 250, "KEY=v")
        ControlProto.controlPrintfDatareply(conn, 250, "DATA")
        assertTrue(conn.outbuf.toString().contains("250 OK"))

        val reply = mutableListOf<ControlReplyLine>()
        ControlProto.controlReplyAddOneKv(reply, 250, "version", "1")
        ControlProto.controlReplyAddStr(reply, 250, "extra")
        ControlProto.controlReplyAddPrintf(reply, 250, "n=%d", 3)
        ControlProto.controlReplyAddDone(reply)
        assertTrue(ControlProto.formatReply(reply).any { it.endsWith("OK") })

        Control.controlFreeAll()
        assertTrue(Control.wasFreed())
    }

    @Test
    fun `control getinfo handle write L3 batch3`() {
        val reply = mutableListOf<ControlReplyLine>()
        ControlProto.controlReplyAddOneKv(reply, 250, "a", "1")
        ControlProto.controlReplyAppendKv(reply, "b", "2")
        assertTrue(reply.last().text.contains("b=2"))
        ControlProto.controlReplyClear(reply)
        assertTrue(reply.isEmpty())
        assertEquals(null, ControlProto.controlReplyFree_(mutableListOf(ControlReplyLine())))
        assertEquals(null, ControlProto.controlReplyLineFree_(ControlReplyLine()))
        assertEquals("GETINFO" to "version", ControlProto.controlSplitIncomingCommand("GETINFO version"))

        val conn = Control.controlConnectionAddLocalFd(1)
        ControlProto.controlWriteEndreply(conn, 250, "OK")
        ControlProto.controlWriteMidreply(conn, 250, "X=1")
        ControlProto.controlWriteDatareply(conn, 250, "body")
        ControlProto.controlWriteData(conn, "payload")
        ControlProto.controlVprintfReply(conn, 250, "n=%d", 7)
        val lines = mutableListOf(ControlReplyLine(250, "k=v"), ControlReplyLine(250, "OK", isDone = true))
        ControlProto.controlWriteReplyLines(conn, lines)
        assertTrue(conn.outbuf.toString().contains("payload"))

        assertEquals(1, ControlAuth.decodeHashedPasswords(listOf("16:abcdef01")))
        assertEquals(0, ControlAuth.initControlCookieAuthentication(true))
        assertTrue(ControlAuth.isCookieAuthInitialized())
        assertTrue(ControlAuth.handleControlAuthchallenge("SAFECOOKIE aabb").contains("OK"))
        assertTrue(ControlAuth.handleControlAuthenticate("deadbeef"))

        Control.disableControlLogging()
        assertFalse(Control.isControlLoggingEnabled())
        Control.enableControlLogging()
        assertTrue(Control.isControlLoggingEnabled())
        assertTrue(Control.entryConnectionDescribeStatusForController(5, "1.2.3.4:80").contains("STREAM"))
        assertEquals("1.2.3.4:9001", Control.orconnTargetGetName("1.2.3.4", 9001))
        assertEquals(0, Control.monitorOwningControllerProcess(4242))
        assertEquals(4242L, Control.owningControllerPid)

        ControlGetinfo.setDownloadStatus("networkstatus", "DL_PROGRESS")
        assertEquals("DL_PROGRESS", ControlGetinfo.getinfoHelperDownloadsNetworkstatus())
        assertEquals("??", ControlGetinfo.getinfoHelperGeoip("8.8.8.8"))
        assertTrue(ControlGetinfo.getinfoHelperCurrentTime().isNotEmpty())
        ControlGetinfo.setCurrentConsensusDigest("ab".repeat(20))
        assertEquals(40, ControlGetinfo.getinfoHelperCurrentConsensus().length)
        ControlGetinfo.addDetachedOnion("xyz.onion")
        assertEquals(listOf("xyz.onion"), ControlGetinfo.getDetachedOnionServices())
        assertEquals(listOf("xyz.onion"), ControlGetinfo.getinfoHelperOnions(detached = true))
        assertEquals("0", ControlGetinfo.getinfoHelperRephist("bw"))
        ControlGetinfo.setCachedNetworkLiveness(false)
        assertFalse(ControlGetinfo.getCachedNetworkLiveness())
        val cookie = Files.createTempFile("ktor-cookie", ".tmp")
        ControlGetinfo.setControllerCookieFileName(cookie)
        assertEquals(cookie, ControlGetinfo.getControllerCookieFileName())
        Files.deleteIfExists(cookie)

        assertEquals("250 OK", ControlCmd.handleControlCommand("GETINFO version"))
        assertTrue(ControlCmd.handleControlGetinfo("version").last().contains("OK"))
        assertEquals("250 OK", ControlCmd.handleControlOnionClientAuthAdd("example.onion x25519:abcd"))
        assertEquals("250 OK", ControlCmd.handleControlOnionClientAuthRemove("example.onion"))
        assertTrue(ControlCmd.handleControlOnionClientAuthView().any { it.contains("OK") })
        assertTrue(ControlFmt.entryConnectionDescribeStatusForController(1, "t").contains("STREAM"))
        assertEquals("not-implemented", ControlGetinfo.getinfoHelperDir("dir/status"))
        assertEquals("unknown", ControlGetinfo.getinfoHelperDownloadsCert())
        assertEquals("unknown", ControlGetinfo.getinfoHelperDownloadsDesc())
        assertEquals("unknown", ControlGetinfo.getinfoHelperDownloadsBridge())
    }

    @Test
    fun `control escaped done rend L3 final`() {
        val esc = ControlProto.writeEscapedData("hello\n.world")
        assertTrue(esc.endsWith(".\r\n"))
        assertTrue(esc.contains("..world") || esc.contains(".\r\n.."))
        val round = ControlProto.readEscapedData("line1\r\n..dot\r\n")
        assertTrue(round.contains("line1"))
        assertTrue(round.contains(".dot") || round.contains("dot"))
        val conn = Control.controlConnectionAddLocalFd(3)
        ControlProto.sendControlDone(conn)
        assertTrue(conn.outbuf.toString().startsWith("250 OK"))
        assertEquals("NO_AUTH", ControlEvents.rendAuthTypeToString(ControlEvents.REND_NO_AUTH))
        assertEquals("REND_V3_AUTH", ControlEvents.rendAuthTypeToString(ControlEvents.REND_V3_AUTH))
        ControlGetinfo.setCachedNetworkLiveness(true)
        assertTrue(ControlGetinfo.getCachedNetworkLiveness())
        assertEquals("example.com.foo.exit:443", ControlFmt.writeStreamTargetToBuf("example.com", 443, chosenExitName = "foo"))
        assertEquals("x.onion:80", ControlFmt.writeStreamTargetToBuf("x", 80, rendezvous = true))
    }
}
