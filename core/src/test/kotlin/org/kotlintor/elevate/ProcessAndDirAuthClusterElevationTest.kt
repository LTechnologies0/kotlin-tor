package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.LogLevel
import org.kotlintor.config.PidFile
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.TorDaemonDirAuthCluster
import java.nio.file.Files
import kotlin.io.path.createTempDirectory

class ProcessAndDirAuthClusterElevationTest {
    @Test
    fun `typed ProcessOptions PidFile NumCPUs ConstrainedSockets Log ServerDNS`() {
        val dir = createTempDirectory("ktor-proc")
        val pidPath = dir.resolve("tor.pid")
        val logPath = dir.resolve("notice.log")
        val cfg = TorrcParser.parse(
            """
            DataDirectory $dir
            PidFile $pidPath
            NumCPUs 2
            OfflineMasterKey 1
            OnionKeyGracePeriod 14
            ConstrainedSockets 1
            ConstrainedSockSize 4096
            SocksPolicy accept 127.0.0.1:*
            SocksPolicy reject *:*
            Log notice file $logPath
            ServerDNSSearchDomains 1
            ServerDNSRandomizeCase 0
            ProtocolWarnings 1
            NoExec 1
            """.trimIndent(),
            dir,
        )
        assertEquals(pidPath, cfg.process.pidFile)
        assertEquals(2, cfg.process.numCpus)
        assertEquals(2, cfg.process.effectiveNumCpus())
        assertTrue(cfg.process.offlineMasterKey)
        assertEquals(14, cfg.process.onionKeyGracePeriodDays)
        assertTrue(cfg.process.constrainedSockets)
        assertEquals(4096, cfg.process.constrainedSockSize)
        assertEquals(2, cfg.process.socksPolicyLines.size)
        assertEquals(LogLevel.NOTICE, cfg.logLevel)
        assertEquals(logPath, cfg.process.logFile)
        assertTrue(cfg.serverDns.searchDomains)
        assertFalse(cfg.serverDns.randomizeCase)
        assertTrue(cfg.process.protocolWarnings)
        assertTrue(cfg.process.noExec)

        val policy = cfg.socksClientPolicy()
        assertTrue(policy.allows("127.0.0.1", 12345))
        assertFalse(policy.allows("8.8.8.8", 12345))

        PidFile.write(cfg.process.pidFile)
        assertTrue(Files.exists(pidPath))
        val written = Files.readString(pidPath).trim().toLong()
        assertEquals(ProcessHandle.current().pid(), written)
        PidFile.delete(cfg.process.pidFile)
        assertFalse(Files.exists(pidPath))
    }

    @Test
    fun `TorDaemonDirAuthCluster quorum round`() {
        val dir = createTempDirectory("ktor-dirauth-cluster")
        val cluster = TorDaemonDirAuthCluster(dir, nAuthorities = 3)
        val result = cluster.runQuorumRound()
        assertTrue(result.quorum, "expected quorum from N-auth peer network")
        assertTrue(result.votesExchanged >= 3)
        assertTrue(result.signaturesExchanged >= 3)
        assertEquals(3, result.fingerprints.size)
        assertTrue(result.consensusBytes > 0)
        assertTrue(Files.exists(dir.resolve("daemon-0/torrc")))
        assertTrue(Files.exists(dir.resolve("daemon-1/keys")))
    }
}
