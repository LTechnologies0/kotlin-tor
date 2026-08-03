package org.kotlintor.cli

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.kotlintor.circuit.CircuitManager
import org.kotlintor.circuit.HopKeys
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.path.PathSelector
import java.nio.file.Path

suspend fun runDebugCircuit(dataDir: Path) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val config = TorConfig(dataDirectory = dataDir)
    val dir = DirectoryClient(dataDir.resolve("dir"))
    val consensus = dir.fetchConsensus()
    val paths = PathSelector(config, dataDir.resolve("state/guards"))
    val mgr = CircuitManager(scope)
    val excluded = mutableSetOf<String>()
    var last: Exception? = null
    repeat(8) { attempt ->
        try {
            val path = paths.select(consensus.relays, extraExclude = excluded, rotateGuard = attempt > 0)
            println(
                "attempt ${attempt + 1}: ${path.guard.nickname} -> ${path.middle.nickname} -> ${path.exit.nickname}",
            )
            val keys = mutableMapOf<String, HopKeys>()
            for (r in listOf(path.guard, path.middle, path.exit)) {
                val docs = dir.fetchServerDescriptors(listOf(r.fingerprintHex))
                val doc = docs.entries.first { it.key.equals(r.fingerprintHex, true) }.value
                val parsed = DescriptorParser.parse(doc, r.fingerprintHex) ?: error("parse ${r.nickname}")
                keys[r.fingerprintHex] = HopKeys(parsed.ntorOnionKey, parsed.ed25519Identity)
            }
            val circ = mgr.buildCircuit(path, keys)
            println("circuit OK id=${circ.id}")
            val stream = circ.openStream("www.torproject.org", 80)
            stream.write("HEAD / HTTP/1.0\r\nHost: www.torproject.org\r\n\r\n".toByteArray())
            val resp = stream.read()
            println("HTTP ${resp.decodeToString().lineSequence().firstOrNull()}")
            stream.close()
            circ.close()
            return
        } catch (e: Exception) {
            last = e
            println("attempt ${attempt + 1} failed: ${e.message}")
            // Exclude mentioned relays when possible by rotating guard next time
        }
    }
    throw IllegalStateException("debug-circuit failed", last)
}
