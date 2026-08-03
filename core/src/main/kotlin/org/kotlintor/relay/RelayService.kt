package org.kotlintor.relay

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCodec
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.circuit.CircuitExtensions
import org.kotlintor.circuit.CgoRelayHopLayer
import org.kotlintor.circuit.HopCrypto
import org.kotlintor.circuit.PeelResult
import org.kotlintor.circuit.buildRelayCell
import org.kotlintor.circuit.parseBeginPayload
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.CreateFast
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.crypto.Ntor
import org.kotlintor.crypto.NtorServer
import org.kotlintor.net.PrivateAddresses
import org.kotlintor.crypto.NtorV3
import org.kotlintor.crypto.X25519KeyPair
import org.kotlintor.dir.DescriptorPublisher
import org.kotlintor.dir.DirAuthSigInbox
import org.kotlintor.dir.DirAuthVoteInbox
import org.kotlintor.dir.DirCache
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.CertsCell
import org.kotlintor.link.LinkAuthCredentials
import org.kotlintor.link.OrAuthenticate
import org.kotlintor.link.OrCertMaterial
import org.kotlintor.link.OrConnection
import org.kotlintor.crypto.Digests
import org.kotlintor.util.readU16be
import org.kotlintor.util.toHex
import org.kotlintor.util.u16be
import org.kotlintor.util.u32be
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.Instant
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * ORPort acceptor: TLS + CERTS (RSA+Ed25519) + CREATE2/ntor(+v3) +
 * EXTEND2 forwarding + BEGIN_DIR directory cache + optional exit BEGIN.
 */
class RelayService(
    private val config: TorConfig,
    private val scope: CoroutineScope,
) {
    private var job: Job? = null
    private var server: ServerSocket? = null
    @Volatile var running: Boolean = false
        private set

    private lateinit var certs: OrCertMaterial
    private lateinit var onionRotator: OnionKeyRotator
    private val onion: X25519KeyPair get() = onionRotator.current()
    private lateinit var edIdentity: Ed25519KeyPair
    private lateinit var edSigning: Ed25519KeyPair
    private lateinit var dirCache: DirCache
    private lateinit var exitPolicy: ExitPolicy

    val identityFingerprint: ByteArray get() = certs.identityFingerprint
    val identityFingerprintHex: String get() = certs.identityFingerprint.toHex().uppercase()
    val ntorOnionKey: ByteArray get() = onion.publicKey
    /** Ed25519 master identity (ntor-v3 NODEID). */
    val ed25519Identity: ByteArray get() = edIdentity.publicKey

    fun start() {
        val or = config.orPort ?: return
        if (!RelaySys.shouldRunRelay(config)) return
        RelaySys.init(config)
        val view = RelayConfigView.fromTorConfig(config)
        view.validate().forEach { System.err.println("relay_config: $it") }
        val transport = TransportConfig.fromTorConfig(config)
        if (transport.parsedListenAddrs().isNotEmpty()) {
            println("ServerTransportListenAddr: ${transport.parsedListenAddrs()}")
        }
        loadOrGenerateKeys()
        // Schedule onion key rotation checks.
        scope.launch {
            while (isActive && running) {
                kotlinx.coroutines.delay(3_600_000)
                if (onionRotator.maybeRotate()) {
                    println("Rotated ntor onion key (lifetime=${config.onionKeyRotationDays}d)")
                    writeLocalDescriptor()
                }
            }
        }
        // C Tor relay_periodic: descriptor republish / metrics flush hints.
        scope.launch {
            val hints = RelayPeriodic.scheduleHints(config)
            val republishMs = (hints["republish_sec"] ?: 18 * 3600) * 1000
            while (isActive && running) {
                kotlinx.coroutines.delay(republishMs.coerceAtLeast(60_000))
                if (RelaySys.shouldPublishDescriptor(config)) {
                    runCatching { writeLocalDescriptor() }
                }
            }
        }
        scope.launch {
            val flushMs = RelayPeriodic.metricsFlushIntervalSec() * 1000
            while (isActive && running) {
                kotlinx.coroutines.delay(flushMs)
                println("relay_metrics ${RelayMetrics.snapshot()}")
            }
        }
        dirCache = DirCache(
            config.dataDirectory.resolve("dir"),
            voteInbox = voteInbox,
            sigInbox = sigInbox,
        )
        exitPolicy = when {
            !config.exitRelay -> ExitPolicy.rejectAll()
            config.exitPolicyLines.isNotEmpty() -> ExitPolicy.fromTorrcLines(config.exitPolicyLines)
            config.reducedExitPolicy -> ExitPolicy.reduced()
            else -> ExitPolicy.rejectAll() // ExitRelay 1 without policy: still closed until configured
        }.withRejectPrivate(config.exitPolicyRejectPrivate)
            .withRejectLocalInterfaces(config.exitPolicyRejectLocalInterfaces)
        exitUdp = if (config.exitRelay) ExitUdp(exitPolicy) else null
        running = true
        job = scope.launch(Dispatchers.IO) {
            val ssf = certs.serverSocketFactory()
            val ss = ssf.createServerSocket() as SSLServerSocket
            ss.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
            ss.bind(InetSocketAddress(or.host, or.port))
            server = ss
            val orLh = ConnectionTable.newListener(or.host, ss.localPort, ConnectionType.OR)
            orLh.markOpen()
            orListenerHandle = orLh
            println(
                "ORPort ${or.host}:${ss.localPort} identity=$identityFingerprintHex " +
                    "ed25519=${ed25519Identity.toHex()} " +
                    "TLS+CERTS(ed)+CREATE2/ntor+ntor-v3+EXTEND2+BEGIN_DIR" +
                    if (config.exitRelay) "+EXIT" else "",
            )
            startDirPortIfConfigured()
            startMetricsPortIfConfigured()
            writeLocalDescriptor()
            while (isActive && running) {
                val sock = runCatching { ss.accept() as SSLSocket }.getOrNull() ?: break
                if (!hibernate.acceptsNewConnections()) {
                    runCatching { sock.close() }
                    continue
                }
                val ip = sock.inetAddress?.hostAddress ?: "unknown"
                if (!dos.allowConnection(ip)) {
                    runCatching { sock.close() }
                    continue
                }
                val orHandle = ConnectionTable.newOr(
                    host = ip,
                    port = sock.port,
                    isClient = true,
                )
                orHandle.markOpen()
                launch {
                    try {
                        handleClient(sock)
                    } finally {
                        dos.releaseConnection(ip)
                        orHandle.markClosed()
                        ConnectionTable.remove(orHandle.id)
                    }
                }
            }
        }
    }

    private fun writeLocalDescriptor() {
        val or = config.orPort ?: return
        val doc = RelayDescriptorBuilder.build(
            RelayDescriptorBuilder.Input(
                nickname = config.nickname,
                address = config.address ?: or.host.ifEmpty { "127.0.0.1" },
                orPort = or.port.let { if (it == 0) server?.localPort ?: 0 else it },
                dirPort = config.dirPort?.port ?: 0,
                identityFingerprintHex = identityFingerprintHex,
                ntorOnionKey = onion.publicKey,
                ed25519Identity = edIdentity.publicKey,
                bandwidth = (
                    config.maxAdvertisedBandwidthBytes.takeIf { it > 0 }
                        ?: config.relayBandwidthRateBytes.takeIf { it > 0 }
                        ?: config.bandwidthRateBytes
                    ).coerceAtLeast(1000),
                contact = config.contactInfo,
                family = config.nodeFamily,
                exitPolicyLines = when {
                    !config.exitRelay -> listOf("reject *:*")
                    config.exitPolicyLines.isNotEmpty() -> config.exitPolicyLines
                    config.reducedExitPolicy -> listOf("ReducedExitPolicy")
                    else -> listOf("reject *:*")
                },
            ),
        )
        lastDescriptor = doc
        val out = config.dataDirectory.resolve("keys").resolve("router-descriptor")
        Files.writeString(out, doc)
        println("Wrote router descriptor ${RelayDescriptorBuilder.digestSha1Hex(doc)} (${doc.length} bytes)")
        if (config.publishServerDescriptor && !config.bridgeRelay) {
            scope.launch(Dispatchers.IO) {
                val results = DescriptorPublisher().publishServerDescriptor(doc)
                RelayMetrics.noteDescriptorPublished()
                for (r in results) {
                    println("DirAuth POST ${r.authority} → ${r.code} ${r.body.take(80)}")
                }
            }
        } else if (config.bridgeRelay) {
            val or = config.orPort
            val status = org.kotlintor.dir.BridgeAuth.BridgeStatus(
                identityHex = identityFingerprintHex.lowercase(),
                nickname = config.nickname,
                ip = or?.host?.ifEmpty { "127.0.0.1" } ?: "127.0.0.1",
                orPort = or?.port?.let { if (it == 0) server?.localPort ?: 0 else it } ?: 0,
                flags = setOf("Running", "Valid", "Bridge"),
                bandwidthKb = (config.bandwidthRateBytes / 1000).toInt().coerceAtLeast(1),
            )
            Files.writeString(
                config.dataDirectory.resolve("bridge-status"),
                org.kotlintor.dir.BridgeAuth.formatNetworkstatusBridges(listOf(status)),
            )
            println("BridgeRelay=1: skipped public DirAuth publish; wrote bridge-status")
        }
    }

    private fun linkAuthCredentials(): LinkAuthCredentials =
        LinkAuthCredentials(
            rsaIdentitySha256 = CertsCell.rsaIdentitySha256(certs.identityCert),
            ed25519IdentityPublic = edIdentity.publicKey,
            ed25519IdentityPrivate = edIdentity.privateKey,
            certsCellPayload = certs.certsCellPayload(edIdentity, edSigning),
        )

    private var dirPortServer: ServerSocket? = null
    private var dirPortJob: Job? = null
    private var dirListenerHandle: org.kotlintor.link.ListenerConnection? = null
    private var orListenerHandle: org.kotlintor.link.ListenerConnection? = null

    private fun startDirPortIfConfigured() {
        val dp = config.dirPort ?: return
        dirPortJob = scope.launch(Dispatchers.IO) {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress(dp.host, dp.port))
            dirPortServer = ss
            val lh = ConnectionTable.newListener(dp.host, ss.localPort, ConnectionType.DIR)
            lh.markOpen()
            dirListenerHandle = lh
            println("DirPort ${dp.host}:${ss.localPort} (HTTP directory cache)")
            while (isActive && running) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                val peer = sock.inetAddress
                if (!PrivateAddresses.allowDirPeer(peer, config.dirAllowPrivateAddresses)) {
                    System.err.println("DirPort reject private peer $peer (DirAllowPrivateAddresses=0)")
                    runCatching { sock.close() }
                    continue
                }
                launch { handleDirPortClient(sock) }
            }
        }
    }

    private fun startMetricsPortIfConfigured() {
        val mp = config.metricsPort ?: return
        val srv = MetricsPortServer(
            config,
            scope,
            identityHex = { identityFingerprintHex },
            counters = metrics,
        )
        srv.start(mp)
        metricsServer = srv
    }

    private suspend fun handleDirPortClient(socket: java.net.Socket) = withContext(Dispatchers.IO) {
        val peerHost = socket.inetAddress?.hostAddress ?: "0.0.0.0"
        val dirHandle = ConnectionTable.newDir(peerHost, socket.port, purpose = "http")
        dirHandle.markOpen()
        try {
            socket.soTimeout = 60_000
            val input = BufferedInputStream(socket.getInputStream())
            val output = BufferedOutputStream(socket.getOutputStream())
            val headerBytes = java.io.ByteArrayOutputStream()
            val buf = ByteArray(1)
            while (headerBytes.size() < 65536) {
                val n = input.read(buf)
                if (n <= 0) break
                headerBytes.write(buf[0].toInt())
                val soFar = headerBytes.toString(StandardCharsets.US_ASCII)
                if (soFar.contains("\r\n\r\n") || soFar.contains("\n\n")) break
            }
            val headers = headerBytes.toString(StandardCharsets.US_ASCII)
            dirHandle.resource = headers.lineSequence().firstOrNull()
                ?.substringAfter(' ')?.substringBefore(' ')
            val contentLength = headers.lineSequence()
                .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
            val body = if (contentLength > 0) {
                input.readNBytes(contentLength.coerceAtMost(2_000_000))
            } else {
                ByteArray(0)
            }
            dirHandle.noteRead((headerBytes.size() + body.size).toLong())
            val resp = dirCache.handleHttp(headers, body)
            output.write(resp)
            output.flush()
            dirHandle.noteWritten(resp.size.toLong())
        } catch (_: Exception) {
        } finally {
            dirHandle.markClosed()
            ConnectionTable.remove(dirHandle.id)
            runCatching { socket.close() }
        }
    }

    private fun loadOrGenerateKeys() {
        val dir = config.dataDirectory.resolve("keys")
        Files.createDirectories(dir)
        certs = OrCertMaterial.loadOrGenerate(dir)
        onionRotator = OnionKeyRotator(
            dir,
            config.onionKeyRotationDays,
            gracePeriodDays = config.process.onionKeyGracePeriodDays,
        )
        onionRotator.loadOrGenerate()
        val edPriv = dir.resolve("ed25519_master_id_secret_key")
        val edPub = dir.resolve("ed25519_master_id_public_key")
        edIdentity = if (Files.exists(edPriv) && Files.size(edPriv) == 32L &&
            Files.exists(edPub) && Files.size(edPub) == 32L
        ) {
            Ed25519KeyPair(Files.readAllBytes(edPriv), Files.readAllBytes(edPub))
        } else {
            Ed25519Keys.generate().also {
                Files.write(edPriv, it.privateKey)
                Files.write(edPub, it.publicKey)
            }
        }
        val signPriv = dir.resolve("ed25519_signing_secret_key")
        val signPub = dir.resolve("ed25519_signing_public_key")
        edSigning = if (Files.exists(signPriv) && Files.size(signPriv) == 32L &&
            Files.exists(signPub) && Files.size(signPub) == 32L
        ) {
            Ed25519KeyPair(Files.readAllBytes(signPriv), Files.readAllBytes(signPub))
        } else {
            Ed25519Keys.generate().also {
                Files.write(signPriv, it.privateKey)
                Files.write(signPub, it.publicKey)
            }
        }
    }

    private data class DirStreamState(
        val buf: StringBuilder = StringBuilder(),
    )

    private data class ExitStreamState(
        val socket: Socket,
        val handle: org.kotlintor.link.ExitConnectionHandle? = null,
        @Volatile var closed: Boolean = false,
    )

    private data class CircState(
        val hop: HopCrypto,
        var next: OrConnection? = null,
        var nextCircId: Long = 0,
        var extending: Boolean = false,
        /** Prop364: CreateOnehop circuits must not be extended. */
        val oneHop: Boolean = false,
        /** Prop359 CGO relay crypt (when negotiated). */
        val cgo: org.kotlintor.circuit.CgoRelayHopLayer? = null,
        val dirStreams: HashMap<Int, DirStreamState> = HashMap(),
        val exitStreams: HashMap<Int, ExitStreamState> = HashMap(),
    )

    private val metrics = MetricsCounters()
    private var metricsServer: MetricsPortServer? = null
    private val dos = config.dosOptions.toGuard()
    private val onionQueue = OnionQueue(maxPending = 100, maxDelayMs = config.maxOnionQueueDelayMs)
    private val hibernate = HibernateAccounting(
        softLimitBytes = config.accountingMaxBytes,
        hardLimitBytes = if (config.accountingMaxBytes > 0) config.accountingMaxBytes * 2 else 0,
        intervalSec = config.accountingIntervalSec,
    )
    private val selfTest = RelaySelfTest()
    private val dnsCache = org.kotlintor.net.DnsResolveCache()
    private var lastDescriptor: String? = null
    private var exitUdp: ExitUdp? = null
    val voteInbox: DirAuthVoteInbox = DirAuthVoteInbox()
    val sigInbox: DirAuthSigInbox = DirAuthSigInbox()

    fun currentDescriptor(): String? = lastDescriptor
    fun hibernateState(): HibernateAccounting.State = hibernate.state()
    fun onionQueueSize(): Int = onionQueue.size()
    fun orportReachable(): Boolean =
        config.assumeReachable || config.assumeReachableIpv6 || selfTest.orportSeemsReachable()
    fun markOrportReachable() = selfTest.foundReachable()
    fun exitUdp(): ExitUdp? = exitUdp

    private suspend fun handleClient(socket: SSLSocket) = withContext(Dispatchers.IO) {
        socket.soTimeout = 120_000
        runCatching { socket.startHandshake() }
        val input = BufferedInputStream(socket.inputStream)
        val output = BufferedOutputStream(socket.outputStream)
        val writeMutex = Mutex()
        var circIdLen = 2
        val circuits = HashMap<Long, CircState>()
        try {
            val first = CellCodec.read(input, circIdLen = 2)
            if (first.command != CellCommand.VERSIONS) {
                socket.close()
                return@withContext
            }
            writeMutex.withLock {
                CellCodec.write(output, Cell(0, CellCommand.VERSIONS, u16be(4) + u16be(5)), circIdLen = 2)
            }
            circIdLen = 4
            writeMutex.withLock {
                CellCodec.write(
                    output,
                    Cell(0, CellCommand.CERTS, certs.certsCellPayload(edIdentity, edSigning)),
                    circIdLen,
                )
                CellCodec.write(output, Cell(0, CellCommand.AUTH_CHALLENGE, certs.authChallengePayload()), circIdLen)
                CellCodec.write(output, Cell(0, CellCommand.NETINFO, buildNetinfo(socket)), circIdLen)
            }

            while (running) {
                val cell = CellCodec.read(input, circIdLen)
                when (cell.command) {
                    CellCommand.AUTHENTICATE -> {
                        // Verify AUTH0003 signature when peer CERTS ed identity is present in cell.
                        runCatching {
                            val body = OrAuthenticate.parse(cell.payload)
                            val ok = OrAuthenticate.verify(body, body.cidEd)
                            println("AUTHENTICATE method=3 verify=$ok")
                        }.onFailure {
                            System.err.println("AUTHENTICATE parse failed: ${it.message}")
                        }
                    }
                    CellCommand.CERTS -> {
                        // Initiator CERTS before AUTHENTICATE — ignore (identity checked via AUTH).
                    }
                    CellCommand.CREATE2 -> {
                        if (!hibernate.acceptsData()) {
                            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
                            continue
                        }
                        if (!onionQueue.tryEnqueue(cell.circId, cell.payload)) {
                            destroy(output, writeMutex, cell.circId, circIdLen, reason = 11) // RESOURCE_LIMIT
                            continue
                        }
                        val job = onionQueue.poll() ?: continue
                        hibernate.note(read = cell.payload.size.toLong())
                        BwHist.noteBytesRead(cell.payload.size.toLong())
                        handleCreate2(
                            Cell(job.circId, CellCommand.CREATE2, job.payload),
                            circuits,
                            output,
                            writeMutex,
                            circIdLen,
                        )
                    }
                    CellCommand.CREATE_FAST -> {
                        if (!hibernate.acceptsData() || !onionQueue.tryEnqueue(cell.circId, cell.payload)) {
                            destroy(output, writeMutex, cell.circId, circIdLen, reason = 11)
                            continue
                        }
                        val job = onionQueue.poll() ?: continue
                        handleCreateFast(
                            Cell(job.circId, CellCommand.CREATE_FAST, job.payload),
                            circuits,
                            output,
                            writeMutex,
                            circIdLen,
                        )
                    }
                    CellCommand.CREATE ->
                        destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
                    CellCommand.DESTROY -> {
                        circuits.remove(cell.circId)?.next?.close()
                    }
                    CellCommand.RELAY, CellCommand.RELAY_EARLY -> {
                        val st = circuits[cell.circId]
                        if (st == null) {
                            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
                            continue
                        }
                        val peel = peelFromClient(st, cell.command.id, cell.payload)
                        if (peel.recognized) {
                            val relay = RelayCell.parse(peel.payload)
                            when (relay.command) {
                                RelayCommand.EXTEND2 -> {
                                    if (st.next != null || st.extending) {
                                        System.err.println("EXTEND2 while already extended")
                                        continue
                                    }
                                    st.extending = true
                                    scope.launch {
                                        handleExtend2(
                                            circId = cell.circId,
                                            st = st,
                                            data = relay.data,
                                            output = output,
                                            writeMutex = writeMutex,
                                            circIdLen = circIdLen,
                                        )
                                    }
                                }
                                RelayCommand.BEGIN_DIR -> {
                                    st.dirStreams[relay.streamId] = DirStreamState()
                                    val connected = buildRelayCell(
                                        RelayCommand.CONNECTED,
                                        relay.streamId,
                                        ByteArray(0),
                                    )
                                    val enc = encryptToClient(st, connected)
                                    writeMutex.withLock {
                                        CellCodec.write(
                                            output,
                                            Cell(cell.circId, CellCommand.RELAY, enc),
                                            circIdLen,
                                        )
                                    }
                                }
                                RelayCommand.BEGIN -> {
                                    scope.launch {
                                        handleExitBegin(
                                            circId = cell.circId,
                                            st = st,
                                            streamId = relay.streamId,
                                            data = relay.data,
                                            output = output,
                                            writeMutex = writeMutex,
                                            circIdLen = circIdLen,
                                        )
                                    }
                                }
                                RelayCommand.RESOLVE -> {
                                    scope.launch {
                                        handleResolve(
                                            circId = cell.circId,
                                            st = st,
                                            streamId = relay.streamId,
                                            data = relay.data,
                                            output = output,
                                            writeMutex = writeMutex,
                                            circIdLen = circIdLen,
                                        )
                                    }
                                }
                                RelayCommand.DATA -> {
                                    val ds = st.dirStreams[relay.streamId]
                                    val es = st.exitStreams[relay.streamId]
                                    if (ds != null) {
                                        ds.buf.append(String(relay.data, StandardCharsets.ISO_8859_1))
                                        if (ds.buf.contains("\r\n\r\n") || ds.buf.contains("\n\n")) {
                                            val resp = dirCache.handleHttp(ds.buf.toString())
                                            sendRelayData(
                                                cell.circId,
                                                st,
                                                relay.streamId,
                                                resp,
                                                output,
                                                writeMutex,
                                                circIdLen,
                                            )
                                            val end = buildRelayCell(
                                                RelayCommand.END,
                                                relay.streamId,
                                                byteArrayOf(6), // DONE
                                            )
                                            val encEnd = encryptToClient(st, end)
                                            writeMutex.withLock {
                                                CellCodec.write(
                                                    output,
                                                    Cell(cell.circId, CellCommand.RELAY, encEnd),
                                                    circIdLen,
                                                )
                                            }
                                            st.dirStreams.remove(relay.streamId)
                                        }
                                    } else if (es != null && !es.closed) {
                                        runCatching {
                                            es.socket.getOutputStream().write(relay.data)
                                            es.socket.getOutputStream().flush()
                                        }.onFailure {
                                            closeExitStream(
                                                cell.circId, st, relay.streamId,
                                                output, writeMutex, circIdLen, reason = 1,
                                            )
                                        }
                                    } else {
                                        System.err.println(
                                            "relay ${cell.circId}: DATA on unknown stream ${relay.streamId}",
                                        )
                                    }
                                }
                                RelayCommand.END -> {
                                    st.dirStreams.remove(relay.streamId)
                                    closeExitStream(
                                        cell.circId, st, relay.streamId,
                                        output, writeMutex, circIdLen,
                                        reason = null, // peer already ENDed
                                    )
                                }
                                RelayCommand.SENDME -> Unit
                                else ->
                                    System.err.println(
                                        "relay ${cell.circId}: unhandled ${relay.command}",
                                    )
                            }
                        } else {
                            // Forward remaining onion layers to next hop.
                            val next = st.next
                            if (next == null) {
                                System.err.println("relay ${cell.circId}: forward with no next hop")
                                continue
                            }
                            val cmd = if (cell.command == CellCommand.RELAY_EARLY) {
                                CellCommand.RELAY_EARLY
                            } else {
                                CellCommand.RELAY
                            }
                            next.send(Cell(st.nextCircId, cmd, peel.payload))
                        }
                    }
                    CellCommand.PADDING, CellCommand.VPADDING, CellCommand.NETINFO -> Unit
                    else -> Unit
                }
            }
        } catch (_: Exception) {
        } finally {
            circuits.values.forEach { st ->
                st.next?.close()
                st.exitStreams.values.forEach { runCatching { it.socket.close() } }
            }
            runCatching { socket.close() }
        }
    }

    private suspend fun handleResolve(
        circId: Long,
        st: CircState,
        streamId: Int,
        data: ByteArray,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        if (!config.exitRelay) {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 4)
            return
        }
        val hostname = data.takeWhile { it.toInt() != 0 }.toByteArray().toString(Charsets.US_ASCII)
        if (hostname.isEmpty()) {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 1)
            return
        }
        val cached = dnsCache.get(hostname)
        val addrs = if (cached != null) {
            cached.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }
        } else {
            withContext(Dispatchers.IO) {
                runCatching { InetAddress.getAllByName(hostname).toList() }.getOrDefault(emptyList())
            }.also { resolved ->
                if (resolved.isNotEmpty()) {
                    dnsCache.put(hostname, resolved.map { it.hostAddress })
                }
            }
        }
        val payload = ArrayList<Byte>()
        for (a in addrs) {
            val raw = a.address
            when (raw.size) {
                4 -> {
                    payload += 0x04.toByte()
                    payload += 4
                    for (b in raw) payload += b
                    // TTL
                    payload += byteArrayOf(0, 0, 0, 60).toList()
                }
                16 -> {
                    payload += 0x06.toByte()
                    payload += 16
                    for (b in raw) payload += b
                    payload += byteArrayOf(0, 0, 0, 60).toList()
                }
            }
        }
        if (payload.isEmpty()) {
            payload += 0xF0.toByte() // error
            payload += 0
        }
        val resolved = buildRelayCell(RelayCommand.RESOLVED, streamId, payload.toByteArray())
        val enc = encryptToClient(st, resolved)
        writeMutex.withLock {
            CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
        }
    }

    private suspend fun handleExitBegin(
        circId: Long,
        st: CircState,
        streamId: Int,
        data: ByteArray,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        val (host, port) = runCatching { parseBeginPayload(data) }.getOrElse {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 1)
            return
        }
        if (!config.exitRelay || !exitPolicy.allows(host, port)) {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 4) // EXITPOLICY
            return
        }
        // C Tor connection_edge: refuse exit BEGIN on one-hop / CreateOnehop when
        // RefuseUnknownExits is enabled (auto → on).
        if (st.oneHop && config.shouldRefuseUnknownExits()) {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 1) // TORPROTOCOL
            return
        }
        val sock = try {
            org.kotlintor.net.OutboundBind.connect(
                host,
                port,
                config.outboundBindForExit(),
                timeoutMs = 15_000,
                constrainedSockSize = if (config.process.constrainedSockets) {
                    config.process.constrainedSockSize
                } else {
                    null
                },
            )
        } catch (_: Exception) {
            sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason = 7) // TIMEOUT/CONNECT
            return
        }
        sock.soTimeout = 0
        val exitHandle = ConnectionTable.newExit(host, port, streamId, circId)
        exitHandle.markOpen()
        st.exitStreams[streamId] = ExitStreamState(sock, exitHandle)
        val connected = buildRelayCell(RelayCommand.CONNECTED, streamId, ByteArray(0))
        val enc = encryptToClient(st, connected)
        writeMutex.withLock {
            CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
        }
        // Clearnet → circuit
        scope.launch(Dispatchers.IO) {
            try {
                val buf = ByteArray(498)
                val input = sock.getInputStream()
                while (isActive && running) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    sendRelayData(
                        circId, st, streamId, buf.copyOf(n),
                        output, writeMutex, circIdLen,
                    )
                }
            } catch (_: Exception) {
            } finally {
                closeExitStream(circId, st, streamId, output, writeMutex, circIdLen, reason = 6)
            }
        }
    }

    private suspend fun sendRelayEnd(
        circId: Long,
        st: CircState,
        streamId: Int,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
        reason: Int,
    ) {
        val end = buildRelayCell(RelayCommand.END, streamId, byteArrayOf(reason.toByte()))
        val enc = encryptToClient(st, end)
        writeMutex.withLock {
            CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
        }
    }

    private suspend fun closeExitStream(
        circId: Long,
        st: CircState,
        streamId: Int,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
        reason: Int?,
    ) {
        val es = st.exitStreams.remove(streamId) ?: return
        if (es.closed) return
        es.closed = true
        runCatching { es.socket.close() }
        es.handle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        if (reason != null) {
            runCatching {
                sendRelayEnd(circId, st, streamId, output, writeMutex, circIdLen, reason)
            }
        }
    }

    private fun peelFromClient(st: CircState, cmd: Int, payload: ByteArray): PeelResult {
        val cgo = st.cgo
        if (cgo != null) {
            val cell = payload.copyOf()
            val sendme = cgo.decryptFromClient(cmd, cell)
            return if (sendme != null) {
                val plain = ByteArray(Cell.FIXED_PAYLOAD_LEN)
                cell.copyOfRange(org.kotlintor.crypto.Cgo.TAG_LEN, org.kotlintor.crypto.Cgo.CELL_DATA_LEN)
                    .copyInto(plain)
                PeelResult(plain, true)
            } else {
                PeelResult(cell, false)
            }
        }
        return st.hop.peelInbound(payload)
    }

    private fun encryptToClient(st: CircState, relay: RelayCell): ByteArray {
        val cgo = st.cgo
        return if (cgo != null) {
            cgo.originateToClient(relay.command.id, relay.toPayload())
        } else {
            st.hop.originateOutbound(relay.toPayload())
        }
    }

    private suspend fun handleCreateFast(
        cell: Cell,
        circuits: HashMap<Long, CircState>,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        if (cell.payload.size < CreateFast.HASH_LEN) {
            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
            return
        }
        try {
            val x = cell.payload.copyOfRange(0, CreateFast.HASH_LEN)
            val (handshake, keys) = CreateFast.serverRespond(x)
            // Server hop keys are swapped relative to client.
            circuits[cell.circId] = CircState(
                hop = HopCrypto.legacy(
                    keys.backwardDigest,
                    keys.forwardDigest,
                    keys.backwardKey,
                    keys.forwardKey,
                ),
            )
            val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
            handshake.copyInto(body)
            writeMutex.withLock {
                CellCodec.write(output, Cell(cell.circId, CellCommand.CREATED_FAST, body), circIdLen)
            }
        } catch (e: Exception) {
            System.err.println("CREATE_FAST failed: ${e.message}")
            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
        }
    }

    private suspend fun handleCreate2(
        cell: Cell,
        circuits: HashMap<Long, CircState>,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        val htype = readU16be(cell.payload, 0)
        val hlen = readU16be(cell.payload, 2)
        val minLen = when (htype) {
            org.kotlintor.crypto.CreateOnehop.HTYPE -> 33
            else -> 64
        }
        if (hlen < minLen || 4 + hlen > cell.payload.size) {
            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
            return
        }
        val hs = cell.payload.copyOfRange(4, 4 + hlen)
        try {
            when (htype) {
                Ntor.HTYPE -> {
                    if (hlen < 84) error("ntor handshake too short")
                    val reply = NtorServer.respond(
                        identity = certs.identityFingerprint,
                        onionPrivate = onion.privateKey,
                        onionPublic = onion.publicKey,
                        clientHandshake = hs,
                    )
                    val r = reply.result
                    circuits[cell.circId] = CircState(
                        hop = HopCrypto.legacy(
                            r.backwardDigest,
                            r.forwardDigest,
                            r.backwardKey,
                            r.forwardKey,
                        ),
                    )
                    metrics.circuitsCreated.incrementAndGet()
                    val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
                    (u16be(reply.handshake.size) + reply.handshake).copyInto(body)
                    writeMutex.withLock {
                        CellCodec.write(output, Cell(cell.circId, CellCommand.CREATED2, body), circIdLen)
                    }
                }
                NtorV3.HTYPE -> {
                    // Always expand ≥160 so CGO (Sf|Sb) and tor1 (first 92) share a prefix.
                    val reply = NtorV3.serverRespond(
                        id = edIdentity.publicKey,
                        onionSk = onion.privateKey,
                        onionPk = onion.publicKey,
                        clientHandshake = hs,
                        keystreamLen = 160,
                        serverMessageFor = { clientCm ->
                            // Successful CREATE2 is the SUBPROTO ack; only echo CC_FIELD_RESPONSE.
                            if (CircuitExtensions.clientRequestedCc(clientCm)) {
                                CircuitExtensions.ccResponse(31)
                            } else {
                                NtorV3.emptyExtensions()
                            }
                        },
                    )
                    val wantCgo = CircuitExtensions.clientRequestedCgo(reply.clientMessage)
                    val ks = reply.keystream
                    if (wantCgo && ks.size >= 160) {
                        circuits[cell.circId] = CircState(
                            hop = HopCrypto.legacy(ByteArray(20), ByteArray(20), ByteArray(16), ByteArray(16)),
                            cgo = CgoRelayHopLayer.fromClientSeeds(
                                ks.copyOfRange(0, 80),
                                ks.copyOfRange(80, 160),
                            ),
                        )
                    } else {
                        circuits[cell.circId] = CircState(
                            hop = HopCrypto.legacy(
                                ks.copyOfRange(20, 40),
                                ks.copyOfRange(0, 20),
                                ks.copyOfRange(56, 72),
                                ks.copyOfRange(40, 56),
                            ),
                        )
                    }
                    metrics.circuitsCreated.incrementAndGet()
                    val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
                    (u16be(reply.handshake.size) + reply.handshake).copyInto(body)
                    writeMutex.withLock {
                        CellCodec.write(output, Cell(cell.circId, CellCommand.CREATED2, body), circIdLen)
                    }
                }
                org.kotlintor.crypto.CreateOnehop.HTYPE -> {
                    val cm = org.kotlintor.crypto.CreateOnehop.clientExtensions(hs)
                    val serverExt = if (CircuitExtensions.clientRequestedCc(cm)) {
                        CircuitExtensions.ccResponse(31)
                    } else {
                        CircuitExtensions.encode(emptyList())
                    }
                    val (response, ks) = org.kotlintor.crypto.CreateOnehop.serverRespond(
                        hs,
                        serverExtensions = serverExt,
                    )
                    circuits[cell.circId] = CircState(
                        hop = HopCrypto.legacy(
                            ks.copyOfRange(20, 40),
                            ks.copyOfRange(0, 20),
                            ks.copyOfRange(56, 72),
                            ks.copyOfRange(40, 56),
                        ),
                        oneHop = true,
                    )
                    metrics.circuitsCreated.incrementAndGet()
                    val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
                    (u16be(response.size) + response).copyInto(body)
                    writeMutex.withLock {
                        CellCodec.write(output, Cell(cell.circId, CellCommand.CREATED2, body), circIdLen)
                    }
                }
                else -> {
                    System.err.println("CREATE2 unsupported HTYPE=$htype")
                    destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
                }
            }
        } catch (e: Exception) {
            System.err.println("CREATE2 failed: ${e.message}")
            destroy(output, writeMutex, cell.circId, circIdLen, reason = 1)
        }
    }

    private suspend fun handleExtend2(
        circId: Long,
        st: CircState,
        data: ByteArray,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        if (st.oneHop) {
            System.err.println("reject EXTEND2 on CreateOnehop circuit")
            destroy(output, writeMutex, circId, circIdLen, reason = 1)
            return
        }
        try {
            val parsed = parseExtend2(data)
            if (!PrivateAddresses.allowExtend(parsed.host, config.extendAllowPrivateAddresses)) {
                System.err.println(
                    "reject EXTEND2 to private ${parsed.host} (ExtendAllowPrivateAddresses=0)",
                )
                destroy(output, writeMutex, circId, circIdLen, reason = 1)
                return
            }
            println(
                "EXTEND2 circ=$circId → ${parsed.host}:${parsed.port} " +
                    "id=${parsed.identity.toHex().uppercase()}",
            )
            val conn = OrConnection(
                parsed.host,
                parsed.port,
                scope,
                linkAuth = linkAuthCredentials(),
                bindLocalHost = config.outboundBindForOr(),
            )
            conn.connect(expectedIdentityHex = parsed.identity.toHex().uppercase())
            val nextCircId = OrConnection.newCircId()
            val inbound = conn.registerCircuit(nextCircId)
            val createPayload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
            val body = ByteArray(4 + parsed.handshake.size)
            body[0] = ((parsed.htype ushr 8) and 0xff).toByte()
            body[1] = (parsed.htype and 0xff).toByte()
            body[2] = ((parsed.handshake.size ushr 8) and 0xff).toByte()
            body[3] = (parsed.handshake.size and 0xff).toByte()
            parsed.handshake.copyInto(body, 4)
            body.copyInto(createPayload)
            conn.send(Cell(nextCircId, CellCommand.CREATE2, createPayload))
            val created = withTimeout(30_000) {
                while (true) {
                    val c = inbound.receive()
                    when (c.command) {
                        CellCommand.CREATED2 -> return@withTimeout c
                        CellCommand.DESTROY -> error("next hop DESTROY during CREATE2")
                        else -> Unit
                    }
                }
                error("unreachable")
            }
            val hlen = readU16be(created.payload, 0)
            val serverHs = created.payload.copyOfRange(2, 2 + hlen)
            val extended = buildRelayCell(RelayCommand.EXTENDED2, 0, u16be(serverHs.size) + serverHs)
            val enc = encryptToClient(st, extended)
            writeMutex.withLock {
                CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
            }
            st.next = conn
            st.nextCircId = nextCircId
            st.extending = false

            // Next → client: add our encryption layer (no digest) and deliver.
            scope.launch(Dispatchers.IO) {
                try {
                    while (isActive && running) {
                        val c = inbound.receive()
                        when (c.command) {
                            CellCommand.RELAY, CellCommand.RELAY_EARLY -> {
                                val wrapped = if (st.cgo != null) {
                                    val cell = c.payload.copyOf()
                                    st.cgo.encryptToClient(c.command.id, cell)
                                    cell
                                } else st.hop.forwardOutbound(c.payload)
                                writeMutex.withLock {
                                    CellCodec.write(
                                        output,
                                        Cell(circId, CellCommand.RELAY, wrapped),
                                        circIdLen,
                                    )
                                }
                            }
                            CellCommand.DESTROY -> {
                                destroy(output, writeMutex, circId, circIdLen, reason = 8)
                                break
                            }
                            else -> Unit
                        }
                    }
                } catch (_: Exception) {
                }
            }
        } catch (e: Exception) {
            st.extending = false
            System.err.println("EXTEND2 failed: ${e.message}")
            val trunc = buildRelayCell(RelayCommand.TRUNCATED, 0, byteArrayOf(6))
            val enc = encryptToClient(st, trunc)
            writeMutex.withLock {
                CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
            }
        }
    }

    private suspend fun sendRelayData(
        circId: Long,
        st: CircState,
        streamId: Int,
        data: ByteArray,
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circIdLen: Int,
    ) {
        var offset = 0
        while (offset < data.size) {
            val n = minOf(498, data.size - offset)
            val cell = buildRelayCell(
                RelayCommand.DATA,
                streamId,
                data.copyOfRange(offset, offset + n),
            )
            val enc = encryptToClient(st, cell)
            writeMutex.withLock {
                CellCodec.write(output, Cell(circId, CellCommand.RELAY, enc), circIdLen)
            }
            offset += n
        }
    }

    private suspend fun destroy(
        output: BufferedOutputStream,
        writeMutex: Mutex,
        circId: Long,
        circIdLen: Int,
        reason: Int,
    ) {
        val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        body[0] = reason.toByte()
        writeMutex.withLock {
            CellCodec.write(output, Cell(circId, CellCommand.DESTROY, body), circIdLen)
        }
    }

    private fun buildNetinfo(socket: SSLSocket): ByteArray {
        val body = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        val now = Instant.now().epochSecond
        u32be(now).copyInto(body, 0)
        val other = (socket.inetAddress?.address) ?: InetAddress.getByName("127.0.0.1").address
        body[4] = if (other.size == 16) 6 else 4
        body[5] = other.size.toByte()
        other.copyInto(body, 6)
        var o = 6 + other.size
        body[o++] = 1
        val my = socket.localAddress?.address ?: InetAddress.getByName("127.0.0.1").address
        body[o++] = if (my.size == 16) 6 else 4
        body[o++] = my.size.toByte()
        my.copyInto(body, o)
        return body
    }

    fun stop() {
        running = false
        RelaySys.shutdown()
        runCatching { server?.close() }
        runCatching { dirPortServer?.close() }
        metricsServer?.stop()
        job?.cancel()
        dirPortJob?.cancel()
        orListenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        orListenerHandle = null
        dirListenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        dirListenerHandle = null
    }
}

internal data class Extend2Request(
    val host: String,
    val port: Int,
    val identity: ByteArray,
    val htype: Int,
    val handshake: ByteArray,
)

internal fun parseExtend2(data: ByteArray): Extend2Request {
    var i = 0
    val nspec = data[i++].toInt() and 0xff
    var host: String? = null
    var port: Int? = null
    var identity: ByteArray? = null
    repeat(nspec) {
        val type = data[i++].toInt() and 0xff
        val len = data[i++].toInt() and 0xff
        val body = data.copyOfRange(i, i + len)
        i += len
        when (type) {
            0 -> {
                require(body.size == 6)
                host = InetAddress.getByAddress(body.copyOfRange(0, 4)).hostAddress
                port = ((body[4].toInt() and 0xff) shl 8) or (body[5].toInt() and 0xff)
            }
            2 -> {
                require(body.size == 20)
                identity = body
            }
        }
    }
    val htype = readU16be(data, i)
    i += 2
    val hlen = readU16be(data, i)
    i += 2
    require(htype != org.kotlintor.crypto.CreateOnehop.HTYPE) {
        "CreateOnehop MUST NOT appear in EXTEND2"
    }
    val handshake = data.copyOfRange(i, i + hlen)
    return Extend2Request(
        host = host ?: error("EXTEND2 missing IPv4"),
        port = port ?: error("EXTEND2 missing port"),
        identity = identity ?: error("EXTEND2 missing identity"),
        htype = htype,
        handshake = handshake,
    )
}
