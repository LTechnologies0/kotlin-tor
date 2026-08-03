package org.kotlintor.cli

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withTimeout
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.circuit.buildCreate2Payload
import org.kotlintor.circuit.parseCreated2Payload
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.Ntor
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.link.OrConnection
import org.kotlintor.path.PathSelector
import org.kotlintor.util.toHex
import java.nio.file.Path

suspend fun runDebugCreate(dataDir: Path) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val config = TorConfig(dataDirectory = dataDir)
    val dir = DirectoryClient(dataDir.resolve("dir"))
    val consensus = dir.fetchConsensus()
    val path = PathSelector(config, dataDir.resolve("state/guards")).select(consensus.relays)
    val guard = path.guard
    println("guard=${guard.nickname} fp=${guard.fingerprintHex} ${guard.ip}:${guard.orPort}")

    val docs = dir.fetchServerDescriptors(listOf(guard.fingerprintHex))
    val doc = docs.entries.firstOrNull { it.key.equals(guard.fingerprintHex, true) }?.value
        ?: error("no descriptor; keys=${docs.keys}")
    val ntorKey = DescriptorParser.parseNtorOnionKey(doc) ?: error("no ntor key")
    println("ntorKey=${ntorKey.toHex()}")
    println("identity=${guard.identity.toHex()}")

    val conn = OrConnection(guard.ip, guard.orPort, scope)
    conn.connect(expectedIdentityHex = guard.fingerprintHex)
    println("negotiatedVersion=${conn.negotiatedVersion}")
    println("certsFp=${conn.peerIdentityFingerprintHex}")

    val circId = OrConnection.newCircId()
    val inbound = conn.registerCircuit(circId)
    val state = Ntor.clientHandshake(guard.identity, ntorKey)
    val payload = ByteArray(org.kotlintor.cell.Cell.FIXED_PAYLOAD_LEN)
    val body = buildCreate2Payload(Ntor.HTYPE, state.handshake)
    body.copyInto(payload)
    println("CREATE2 circId=$circId (${circId.toString(16)}) handshake=${state.handshake.size} bytes")
    println("handshakeHex=${state.handshake.toHex()}")
    conn.send(Cell(circId, CellCommand.CREATE2, payload))

    val cell = withTimeout(20_000) { inbound.receive() }
    println(
        "response cmd=${cell.command} circId=${cell.circId} " +
            "b0=${cell.payload.firstOrNull()?.toInt()?.and(0xff)}",
    )
    when (cell.command) {
        CellCommand.CREATED2 -> {
            val hs = parseCreated2Payload(cell.payload)
            println("CREATED2 serverHs=${hs.size}")
            Ntor.clientFinish(state, guard.identity, ntorKey, hs)
            println("ntor OK")
        }
        CellCommand.DESTROY ->
            println("DESTROY reason=${cell.payload[0].toInt() and 0xff}")
        else -> println("unexpected payload=${cell.payload.copyOf(16).toHex()}")
    }
    conn.close()
}
