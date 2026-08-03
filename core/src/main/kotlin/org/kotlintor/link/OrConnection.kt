package org.kotlintor.link

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCodec
import org.kotlintor.cell.CellCommand
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.EwmaCircuitMuxPolicy
import org.kotlintor.crypto.Digests
import org.kotlintor.os.LinuxTcpInfo
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.readU16be
import org.kotlintor.util.toHex
import org.kotlintor.util.u16be
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLSocket

/**
 * Credentials for initiator AUTHENTICATE (Ed25519-SHA256-RFC5705) when acting as a relay.
 */
data class LinkAuthCredentials(
    val rsaIdentitySha256: ByteArray,
    val ed25519IdentityPublic: ByteArray,
    val ed25519IdentityPrivate: ByteArray,
    val certsCellPayload: ByteArray,
)

/**
 * TLS OR connection + link handshake (VERSIONS / CERTS / AUTH_CHALLENGE / NETINFO).
 * Optional [linkAuth] enables post-challenge CERTS+AUTHENTICATE when method 3 is advertised
 * and a TLS exporter is available (JDK 25+) or [tlsExporter] is injected.
 */
class OrConnection(
    private val host: String,
    private val port: Int,
    private val scope: CoroutineScope,
    private val linkAuth: LinkAuthCredentials? = null,
    private val tlsExporter: OrAuthenticate.TlsExporter? = null,
    /** Optional plain TCP dialer (e.g. PT SOCKS5 → bridge). */
    private val dialer: (suspend () -> Socket)? = null,
    /** OutboundBindAddressOR — bind local address before connect. */
    private val bindLocalHost: String? = null,
    /** ConstrainedSockets buffer size (bytes); null disables. */
    private val constrainedSockSize: Int? = null,
) {
    private var socket: SSLSocket? = null
    private var input: BufferedInputStream? = null
    private var output: BufferedOutputStream? = null
    private val writeMutex = Mutex()
    private var readerJob: Job? = null
    private var paddingJob: Job? = null
    private var flushJob: Job? = null
    private val circuitChannels = ConcurrentHashMap<Long, Channel<Cell>>()
    private val controlCells = Channel<Cell>(Channel.UNLIMITED)
    private var circIdLen: Int = 2
    var negotiatedVersion: Int = 0
        private set
    /** RSA identity fingerprint from CERTS cell, if parsed. */
    var peerIdentityFingerprint: ByteArray? = null
        private set
    var peerEd25519Identity: ByteArray? = null
        private set
    var peerCertsPayload: ByteArray? = null
        private set
    /** Parsed AUTH_CHALLENGE (for initiator AUTHENTICATE when acting as relay). */
    var authChallenge: AuthChallenge.Parsed? = null
        private set
    /** True when we successfully sent AUTHENTICATE (exporter + SIG). */
    var authenticatedAsInitiator: Boolean = false
        private set
    val peerIdentityFingerprintHex: String?
        get() = peerIdentityFingerprint?.toHex()

    /** Negotiated padding interval (prop254); updated by PADDING_NEGOTIATE. */
    @Volatile var paddingIntervalMs: Long = PADDING_INTERVAL_MS
        private set

    /** C Tor Schedulers= (default Vanilla — unlimited flush). */
    val writeBudget: WriteBudget = WriteBudget(SchedulerType.VANILLA)

    /** Per-channel circuitmux (C Tor `circuitmux_t` + EWMA). */
    val circuitMux: CircuitMux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = 30.0))

    /** Netflow / channel padding decision machine (prop254). */
    val channelPadding: ChannelPaddingController = ChannelPaddingController()

    /** Optional [ConnectionTable] OR handle for hierarchy accounting. */
    var tableHandle: OrConnectionHandle? = null

    /** channel_t outbuf/inbuf accounting. */
    val orChannel: OrChannel = OrChannel(remoteAddr = host, remotePort = port).also {
        ChannelTable.register(it)
    }

    val isOpen: Boolean get() = socket?.isConnected == true && socket?.isClosed == false

    fun registerCircuit(circId: Long): Channel<Cell> {
        val ch = Channel<Cell>(Channel.UNLIMITED)
        circuitChannels[circId] = ch
        circuitMux.attach(circId, initialCells = 0)
        channelPadding.hasCircuitUsage = true
        return ch
    }

    fun unregisterCircuit(circId: Long) {
        circuitChannels.remove(circId)?.close()
        circuitMux.detach(circId)
        if (circuitChannels.isEmpty()) channelPadding.hasCircuitUsage = false
    }

    suspend fun connect(expectedIdentityHex: String? = null) = withContext(Dispatchers.IO) {
        val handle = ConnectionTable.newOr(host, port, isClient = true)
        handle.markHandshaking()
        tableHandle = handle
        orChannel.orConnId = handle.id
        try {
            connectInner(expectedIdentityHex)
            handle.identityFpHex = peerIdentityFingerprintHex
            handle.circMuxAttached = true
            handle.channelId = orChannel.globalId
            handle.markOpen()
            orChannel.markOpen()
            ChannelSchedulerPending.register(orChannel) { flushMux(maxItems = 16) }
        } catch (e: Exception) {
            handle.markClosed()
            ConnectionTable.remove(handle.id)
            orChannel.markClosed()
            ChannelTable.remove(orChannel.globalId)
            ChannelSchedulerPending.unregister(orChannel.globalId)
            tableHandle = null
            throw e
        }
    }

    private suspend fun connectInner(expectedIdentityHex: String?) {
        val plain = if (dialer != null) {
            dialer.invoke()
        } else {
            org.kotlintor.net.OutboundBind.connect(
                host,
                port,
                bindLocalHost,
                timeoutMs = 15_000,
                constrainedSockSize = constrainedSockSize,
            ).also {
                it.soTimeout = 20_000
            }
        }
        if (constrainedSockSize != null && constrainedSockSize > 0) {
            val n = constrainedSockSize.coerceIn(512, 65536)
            runCatching {
                plain.receiveBufferSize = n
                plain.sendBufferSize = n
            }
        }
        plain.soTimeout = 20_000
        val ssl = TorSsl.socketFactory.createSocket(plain, host, port, true) as SSLSocket
        ssl.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
        ssl.sslParameters = ssl.sslParameters.apply {
            endpointIdentificationAlgorithm = null
        }
        ssl.soTimeout = 20_000
        ssl.startHandshake()
        socket = ssl
        input = BufferedInputStream(ssl.inputStream)
        output = BufferedOutputStream(ssl.outputStream)
        performHandshake()
        if (expectedIdentityHex != null) {
            val peer = peerIdentityFingerprintHex
            if (peer != null && !peer.equals(expectedIdentityHex, ignoreCase = true)) {
                throw IllegalStateException(
                    "OR identity mismatch: expected $expectedIdentityHex got $peer at $host:$port",
                )
            }
        }
        ssl.soTimeout = 60_000
        readerJob = scope.launch(Dispatchers.IO) { readLoop() }
        paddingJob = scope.launch(Dispatchers.IO) {
            while (isActive && isOpen) {
                val delayMs = channelPadding.nextCheckDelayMs().coerceIn(50, paddingIntervalMs)
                kotlinx.coroutines.delay(delayMs)
                when (channelPadding.decide()) {
                    ChannelPaddingDecision.PADDING_SENT -> {
                        runCatching {
                            send(Cell(0, CellCommand.PADDING, ByteArray(Cell.FIXED_PAYLOAD_LEN)))
                        }
                    }
                    else -> Unit
                }
            }
        }
        // Periodic cmux flush under KIST / KIST_LITE (scheduler_kist tick lite).
        if (writeBudget.type == SchedulerType.KIST || writeBudget.type == SchedulerType.KIST_LITE) {
            flushJob = scope.launch(Dispatchers.IO) {
                while (isActive && isOpen) {
                    kotlinx.coroutines.delay(10)
                    runCatching { flushMux(maxItems = 16) }
                    runCatching { ChannelSchedulerPending.drainFair(maxChannels = 8) }
                }
            }
        }
    }

    private suspend fun performHandshake() {
        circIdLen = 2
        val ourVersions = listOf(4, 5)
        val versionsPayload = ourVersions.fold(ByteArray(0)) { acc, v -> acc + u16be(v) }
        send(Cell(0, CellCommand.VERSIONS, versionsPayload), circIdLen = 2)
        var sawVersions = false
        var sawNetinfo = false
        val responderCells = ArrayList<ByteArray>()
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline && (!sawVersions || !sawNetinfo)) {
            val cell = withContext(Dispatchers.IO) { CellCodec.read(input!!, circIdLen) }
            when (cell.command) {
                CellCommand.VERSIONS -> {
                    responderCells += CellCodec.encode(cell, circIdLen = 2)
                    val peer = mutableListOf<Int>()
                    var i = 0
                    while (i + 1 < cell.payload.size) {
                        peer += readU16be(cell.payload, i)
                        i += 2
                    }
                    negotiatedVersion = ourVersions.intersect(peer.toSet()).maxOrNull()
                        ?: error("no mutually supported link version: us=$ourVersions peer=$peer")
                    circIdLen = if (negotiatedVersion >= 4) 4 else 2
                    sawVersions = true
                }
                CellCommand.CERTS -> {
                    responderCells += CellCodec.encode(cell, circIdLen)
                    peerCertsPayload = cell.payload
                    val parsed = CertsCell.parse(cell.payload)
                    peerIdentityFingerprint = parsed.rsaIdentityFingerprint
                    peerEd25519Identity = parsed.ed25519Identity
                }
                CellCommand.AUTH_CHALLENGE -> {
                    responderCells += CellCodec.encode(cell, circIdLen)
                    authChallenge = AuthChallenge.parse(cell.payload)
                }
                CellCommand.VPADDING, CellCommand.PADDING -> {
                    channelPadding.noteCellActivity()
                }
                CellCommand.PADDING_NEGOTIATE -> {
                    val (cmd, low, high) = PaddingNegotiate.parse(cell.payload)
                    channelPadding.applyNegotiate(cmd, low, high)
                    if (cmd == PaddingNegotiate.COMMAND_START) {
                        paddingIntervalMs = ((low + high) / 2L).coerceAtLeast(500)
                    }
                }
                CellCommand.NETINFO -> {
                    responderCells += CellCodec.encode(cell, circIdLen)
                    val netinfo = buildNetinfo()
                    send(netinfo, circIdLen)
                    tryInitiatorAuthenticate(
                        responderCells = responderCells,
                        initiatorVersions = CellCodec.encode(
                            Cell(0, CellCommand.VERSIONS, versionsPayload),
                            circIdLen = 2,
                        ),
                        initiatorNetinfo = CellCodec.encode(netinfo, circIdLen),
                    )
                    sawNetinfo = true
                }
                else -> controlCells.trySend(cell)
            }
        }
        check(sawVersions && sawNetinfo) {
            "OR handshake incomplete (v=$sawVersions netinfo=$sawNetinfo negotiated=$negotiatedVersion)"
        }
        if (negotiatedVersion >= 5) {
            runCatching {
                send(PaddingNegotiate.start(itoLowMs = 1_500, itoHighMs = 9_500), circIdLen)
                channelPadding.applyNegotiate(PaddingNegotiate.COMMAND_START, 1_500, 9_500)
                paddingIntervalMs = 1_500L + ((9_500L - 1_500L) / 2)
            }
        }
    }

    private suspend fun tryInitiatorAuthenticate(
        responderCells: List<ByteArray>,
        initiatorVersions: ByteArray,
        initiatorNetinfo: ByteArray,
    ) {
        val creds = linkAuth ?: return
        val challenge = authChallenge ?: return
        if (AuthChallenge.METHOD_ED25519_SHA256_RFC5705 !in challenge.methods) return
        val peerEd = peerEd25519Identity ?: return
        val peerCerts = peerCertsPayload ?: return
        val ssl = socket ?: return
        val exporter = tlsExporter ?: OrAuthenticate.exporterFromSsl(ssl) ?: return
        val sid = CertsCell.rsaIdentitySha256FromCertsPayload(peerCerts) ?: return
        val cid = creds.rsaIdentitySha256
        val ourCertsCell = Cell(0, CellCommand.CERTS, creds.certsCellPayload)
        send(ourCertsCell, circIdLen)
        val slog = Digests.sha256(responderCells.fold(ByteArray(0)) { a, b -> a + b })
        val clog = Digests.sha256(
            initiatorVersions + CellCodec.encode(ourCertsCell, circIdLen) + initiatorNetinfo,
        )
        val scert = try {
            val peer = ssl.session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate
            if (peer != null) OrAuthenticate.sha256TlsCert(peer) else Digests.sha256(ByteArray(0))
        } catch (_: Exception) {
            Digests.sha256(ByteArray(0))
        }
        val tlsSecrets = try {
            OrAuthenticate.exportTlsSecrets(exporter, cid)
        } catch (_: Exception) {
            return
        }
        val body = OrAuthenticate.build(
            cidRsaSha256 = cid,
            sidRsaSha256 = sid,
            cidEd = creds.ed25519IdentityPublic,
            sidEd = peerEd,
            slog = slog,
            clog = clog,
            scertSha256 = scert,
            tlsSecrets = tlsSecrets,
            linkEdPrivate = creds.ed25519IdentityPrivate,
        )
        send(OrAuthenticate.toCell(body), circIdLen)
        authenticatedAsInitiator = true
    }

    private fun buildNetinfo(): Cell {
        val now = Instant.now().epochSecond
        val myAddr = socket!!.localAddress.address
        val orAddr = InetAddress.getByName(host).address
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        var o = 0
        payload[o++] = ((now ushr 24) and 0xff).toByte()
        payload[o++] = ((now ushr 16) and 0xff).toByte()
        payload[o++] = ((now ushr 8) and 0xff).toByte()
        payload[o++] = (now and 0xff).toByte()
        payload[o++] = 4
        payload[o++] = orAddr.size.toByte()
        orAddr.copyInto(payload, o)
        o += orAddr.size
        payload[o++] = 1
        payload[o++] = if (myAddr.size == 16) 6 else 4
        payload[o++] = myAddr.size.toByte()
        myAddr.copyInto(payload, o)
        return Cell(0, CellCommand.NETINFO, payload)
    }

    private suspend fun readLoop() {
        try {
            while (scope.isActive && isOpen) {
                val cell = CellCodec.read(input!!, circIdLen)
                val ch = circuitChannels[cell.circId]
                if (ch != null) ch.send(cell) else controlCells.trySend(cell)
            }
        } catch (_: Exception) {
            circuitChannels.values.forEach { it.close() }
            controlCells.close()
        }
    }

    /**
     * Send a cell. Under KIST / KIST_LITE, circuit cells are enqueued on the
     * cmux and drained by [flushMux] (live OR cmux queue path). Control cells
     * (circId=0) and Vanilla always write immediately.
     * [channel] tracks outbuf byte accounting for KIST / channel_t parity.
     */
    suspend fun send(cell: Cell, circIdLen: Int = this.circIdLen) {
        val encoded = CellCodec.encode(cell, circIdLen)
        val useMux = cell.circId != 0L &&
            (writeBudget.type == SchedulerType.KIST || writeBudget.type == SchedulerType.KIST_LITE)
        if (useMux) {
            if (!circuitMux.isAttached(cell.circId)) {
                circuitMux.attach(cell.circId)
            }
            if (!circuitMux.enqueue(cell.circId, encoded)) {
                writeEncodedDirect(encoded, cell.circId)
                return
            }
            orChannel.queueOut(encoded)
            ChannelSchedulerPending.notePending(orChannel)
            flushMux(maxItems = 32)
            return
        }
        writeEncodedDirect(encoded, cell.circId)
    }

    private fun kistSocketInfo(): KistMath.SocketInfo? {
        val base = if (writeBudget.type == SchedulerType.KIST) {
            socket?.let { LinuxTcpInfo.query(it)?.toKist() }
        } else {
            null
        }
        return when {
            base != null -> base.copy(outbufLen = orChannel.outbufBytes)
            orChannel.outbufBytes > 0 -> KistMath.SocketInfo(outbufLen = orChannel.outbufBytes)
            else -> null
        }
    }

    private suspend fun writeEncodedDirect(
        encoded: ByteArray,
        circId: Long,
        noteXmit: Boolean = true,
    ) {
        writeMutex.withLock {
            var spins = 0
            while (!writeBudget.tryAllowFull(encoded.size)) {
                writeBudget.refill(kistSocketInfo())
                if (++spins > 64) break
                kotlinx.coroutines.delay(1)
            }
            withContext(Dispatchers.IO) {
                output!!.write(encoded)
                output!!.flush()
            }
            channelPadding.noteCellActivity()
            tableHandle?.noteWritten(encoded.size.toLong())
            // Vanilla path: account write on channel without lingering outbuf.
            orChannel.bytesWrittenAccount(encoded.size)
            if (noteXmit && circId != 0L) {
                circuitMux.notifyXmit(circId, 1)
            }
            org.kotlintor.stats.ConnStats.noteOrConnBytes(
                connId = tableHandle?.id
                    ?: (System.identityHashCode(this).toLong() and 0xffff_ffffL),
                numRead = 0,
                numWritten = encoded.size.toLong(),
            )
        }
    }

    /** Drain mux cell/destroy queues into the TLS write path (cmux flush + KIST budget). */
    suspend fun flushMux(maxItems: Int = 32): Int {
        // Multi-circuit: round-robin fair drain; single active keeps EWMA pick path.
        val batch = if (circuitMux.numActive() > 1) {
            circuitMux.flushFair(maxItems)
        } else {
            circuitMux.flush(maxItems)
        }
        var n = 0
        for (item in batch) {
            if (writeBudget.type == SchedulerType.KIST || writeBudget.type == SchedulerType.KIST_LITE) {
                writeBudget.refill(kistSocketInfo())
            }
            when (item) {
                is CircuitMux.FlushItem.Destroy -> {
                    val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
                    payload[0] = item.reason.toByte()
                    val encoded = CellCodec.encode(
                        Cell(item.circId, CellCommand.DESTROY, payload),
                        circIdLen,
                    )
                    writeEncodedDirect(encoded, item.circId, noteXmit = false)
                    n++
                }
                is CircuitMux.FlushItem.Cell -> {
                    if (!writeBudget.tryAllowFull(item.payload.size)) {
                        circuitMux.enqueue(item.circId, item.payload)
                        // Re-queue remaining unflushed batch cells to preserve order fairness.
                        val rest = batch.drop(n + 1).filterIsInstance<CircuitMux.FlushItem.Cell>()
                        for (r in rest.asReversed()) {
                            circuitMux.enqueue(r.circId, r.payload)
                        }
                        return n
                    }
                    writeMutex.withLock {
                        withContext(Dispatchers.IO) {
                            output!!.write(item.payload)
                            output!!.flush()
                        }
                        channelPadding.noteCellActivity()
                        tableHandle?.noteWritten(item.payload.size.toLong())
                        orChannel.popOut() // matches queueOut in send()
                        org.kotlintor.stats.ConnStats.noteOrConnBytes(
                            connId = tableHandle?.id
                                ?: (System.identityHashCode(this).toLong() and 0xffff_ffffL),
                            numRead = 0,
                            numWritten = item.payload.size.toLong(),
                        )
                    }
                    n++
                }
            }
        }
        return n
    }

    /** Apply consensus cmux / padding params (CircuitPriorityHalflifeMsec, nf_*). */
    fun applyConsensusParams(params: Map<String, Long>) {
        val ewma = circuitMux.policy() as? EwmaCircuitMuxPolicy
        ewma?.applyConsensusParams(params)
        channelPadding.params = ChannelPaddingParams.fromConsensus(
            params.mapValues { it.value.toInt() },
            reduced = channelPadding.params.reduced,
        )
    }

    fun close() {
        flushJob?.cancel()
        paddingJob?.cancel()
        readerJob?.cancel()
        runCatching { socket?.close() }
        tableHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        tableHandle = null
        orChannel.markClosed()
        ChannelTable.remove(orChannel.globalId)
        ChannelSchedulerPending.unregister(orChannel.globalId)
        circuitChannels.values.forEach { it.close() }
        controlCells.close()
    }

    companion object {
        const val PADDING_INTERVAL_MS: Long = 15_000

        fun newCircId(): Long {
            val r = SecureRandomSource.nextBytes(4)
            var id = 0L
            for (b in r) id = (id shl 8) or (b.toInt() and 0xff).toLong()
            id = id or 0x80000000L
            if ((id and 0x7fffffffL) == 0L) id = 0x80000001L
            return id
        }
    }
}
