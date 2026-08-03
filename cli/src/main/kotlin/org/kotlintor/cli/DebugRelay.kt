package org.kotlintor.cli

import kotlinx.coroutines.delay
import org.kotlintor.TorDaemon
import org.kotlintor.circuit.Circuit
import org.kotlintor.circuit.CircuitManager
import org.kotlintor.circuit.HopKeys
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.dir.RouterStatus
import org.kotlintor.link.OrConnection
import org.kotlintor.path.CircuitPath
import org.kotlintor.util.hexToBytes
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.Instant

/**
 * Start a local TLS ORPort and build a 3-hop circuit with it as the guard
 * (CREATE2 locally, EXTEND2 to the public network), then BEGIN_DIR against local.
 */
suspend fun runDebugRelay(dataDir: Path, orPort: Int = 19090) {
    val config = TorConfig(
        dataDirectory = dataDir,
        clientOnly = false,
        orPort = ListenSpec("127.0.0.1", orPort),
        socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
        controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
    )
    val daemon = TorDaemon(config)
    try {
        daemon.start(buildCircuit = false)
        delay(400)
        val c = daemon.client.consensusOrNull() ?: error("no consensus")
        check(daemon.relay.running) { "relay did not start" }
        val idHex = daemon.relay.identityFingerprintHex
        val onion = daemon.relay.ntorOnionKey
        println("local ORPort 127.0.0.1:$orPort identity=$idHex")

        val ed = daemon.relay.ed25519Identity
        val guard = RouterStatus(
            nickname = "kotlinTorLocal",
            identity = hexToBytes(idHex),
            digest = ByteArray(20),
            publication = Instant.now(),
            ip = "127.0.0.1",
            orPort = orPort,
            dirPort = 0,
            flags = setOf("Running", "Fast", "Guard", "Stable", "V2Dir"),
            version = null,
            proto = mapOf("Relay" to "1-4", "FlowCtrl" to "1"),
            bandwidth = 1_000_000,
            ntorOnionKey = onion,
            ed25519Identity = ed,
        )
        val dir = DirectoryClient(dataDir.resolve("dir"))
        val middles = c.relays
            .filter { it.isRunning && it.isFast && it.isStable && it.isGuard && it.orPort in listOf(443, 9001) }
            .shuffled()
            .take(12)
        val exits = c.relays.filter { it.isExit && it.isRunning && it.isFast }.shuffled()
        require(middles.isNotEmpty() && exits.isNotEmpty())
        var last: Exception? = null
        for (middle in middles) {
            val exit = exits.first { it.fingerprintHex != middle.fingerprintHex }
            try {
                val docs = dir.fetchServerDescriptors(listOf(middle.fingerprintHex, exit.fingerprintHex))
                val midParsed = DescriptorParser.parse(
                    docs.entries.first { it.key.equals(middle.fingerprintHex, true) }.value,
                    middle.fingerprintHex,
                ) ?: error("bad middle descriptor")
                val exitParsed = DescriptorParser.parse(
                    docs.entries.first { it.key.equals(exit.fingerprintHex, true) }.value,
                    exit.fingerprintHex,
                ) ?: error("bad exit descriptor")
                val path = CircuitPath(guard, middle, exit)
                val keys = mapOf(
                    guard.fingerprintHex to HopKeys(onion, ed),
                    middle.fingerprintHex to HopKeys(midParsed.ntorOnionKey, midParsed.ed25519Identity),
                    exit.fingerprintHex to HopKeys(exitParsed.ntorOnionKey, exitParsed.ed25519Identity),
                )
                println(
                    "building 3-hop: local(ntor-v3) → ${middle.nickname} → ${exit.nickname}",
                )
                val circ = CircuitManager(daemon.scope).buildCircuit(path, keys)
                println("3-hop via local TLS ORPort OK circ=${circ.id}")
                circ.close()

                runLocalBeginDir(daemon, guard)
                println("RELAY DEBUG OK")
                return
            } catch (e: Exception) {
                last = e
                System.err.println("attempt via ${middle.nickname} failed: ${e.message}")
            }
        }
        throw IllegalStateException("all EXTEND2 attempts failed", last)
    } finally {
        daemon.stop()
    }
}

/** One-hop CREATE2 + BEGIN_DIR GET consensus from the local OR's DirCache. */
private suspend fun runLocalBeginDir(daemon: TorDaemon, guard: RouterStatus) {
    val conn = OrConnection(guard.ip, guard.orPort, daemon.scope)
    conn.connect(expectedIdentityHex = guard.fingerprintHex)
    val circId = OrConnection.newCircId()
    val inbound = conn.registerCircuit(circId)
    val circ = Circuit(circId, conn, daemon.scope, inbound)
    circ.createFirstHop(
        guard,
        HopKeys(daemon.relay.ntorOnionKey, daemon.relay.ed25519Identity),
    )
    val stream = circ.openDirStream()
    val req = "GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    stream.write(req.toByteArray(StandardCharsets.US_ASCII))
    val resp = stream.readHttpResponse(maxBytes = 2 * 1024 * 1024)
    val text = String(resp, StandardCharsets.UTF_8)
    check(text.contains("HTTP/1.0 200") || text.contains("network-status-version")) {
        "BEGIN_DIR failed: ${text.take(200)}"
    }
    println("BEGIN_DIR local consensus OK (${resp.size} bytes)")
    circ.close()
}
