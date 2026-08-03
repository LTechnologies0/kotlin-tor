package org.kotlintor.circuit

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.crypto.Ntor
import org.kotlintor.crypto.NtorV3
import org.kotlintor.dir.RouterStatus
import org.kotlintor.hs.HsNtor
import org.kotlintor.link.OrConnection
import org.kotlintor.path.CircuitBuildTimeout
import org.kotlintor.path.CircuitPath
import org.kotlintor.path.PathBiasTracker
import org.kotlintor.relay.RepHist
import org.kotlintor.util.SecureRandomSource
import java.net.InetAddress

data class HopKeys(
    val ntorOnionKey: ByteArray,
    val ed25519Identity: ByteArray? = null,
)

class Circuit(
    val id: Long,
    private val conn: OrConnection,
    private val scope: CoroutineScope,
    private val inbound: Channel<Cell>,
) {
    private val layers = CircuitLayerCake()
    private val mutex = Mutex()
    private val circuitRelay = Channel<RelayCell>(Channel.UNLIMITED)
    private var nextStreamId = 1
    private val streams = mutableMapOf<Int, Channel<RelayCell>>()
    var meta: CircuitMeta = CircuitMeta(CircuitKind.Origin(id))
    val edgeStreams: EdgeConnectionTable = EdgeConnectionTable()
    private val created2 = Channel<Cell>(1)
    /** Classic fixed windows; swapped for [CongestionControl] when prop324 negotiates. */
    private var flow: CircWindows = ClassicWindows(CircuitFlowControl())
    /** KH from the last hop's ntor (for ESTABLISH_INTRO). */
    var lastHopKh: ByteArray? = null
        private set
    /** Negotiated `cc_sendme_inc`, or null when using classic windows. */
    var congestionSendmeInc: Int? = null
        private set

    /**
     * Send CC_FIELD_REQUEST on ntor-v3 CREATE/EXTEND (default on).
     * When the hop replies with CC_FIELD_RESPONSE, [enableCongestionControl] runs.
     */
    var requestCongestionControl: Boolean = true

    /** Prefer CGO when every hop advertises Relay=5+6 (CircuitManager gates path). */
    var requestCgo: Boolean = true

    /** True after a hop negotiated CGO; subsequent hops on this circuit should match. */
    var cgoNegotiated: Boolean = false
        private set

    /** Prop302 client intro-circuit hide machine (optional DROP burst after INTRODUCE1). */
    var circuitPaddingEnabled: Boolean = true
    /** When true, send RELAY PADDING_NEGOTIATE before intro DROP burst. */
    var circuitPaddingNegotiate: Boolean = true
    private val introPad =
        CircuitPaddingSession(
            CircuitPaddingMachines.clientHideIntro(),
            sendDrop = { cell -> sendRelay(cell) },
            sendNegotiate = { cell -> sendRelay(cell) },
        )

    /** First stream attachment time (circuit dirty clock). */
    @Volatile var dirtySinceMs: Long? = null
        private set
    /** When the last stream closed (unused-circuit timeout clock). */
    @Volatile var unusedSinceMs: Long? = null
        private set
    val openStreamCount: Int get() = streams.size

    /** Half-closed streams (C Tor `half_edge_t`) after local END. */
    val halfEdges = HalfEdgeSet()

    /** Optional path-bias hooks (wired by [CircuitManager]). */
    var pathBiasTracker: PathBiasTracker? = null
    var pathBiasGuardFp: String? = null

    private interface CircWindows {
        suspend fun beforeOutboundData()
        suspend fun onInboundData(digestAfterCell: ByteArray): ByteArray?
        suspend fun onInboundSendme()
    }

    private class ClassicWindows(private val inner: CircuitFlowControl) : CircWindows {
        override suspend fun beforeOutboundData() = inner.beforeOutboundData()
        override suspend fun onInboundData(digestAfterCell: ByteArray) = inner.onInboundData(digestAfterCell)
        override suspend fun onInboundSendme() = inner.onInboundSendme()
    }

    private class CcWindows(private val inner: CongestionControl) : CircWindows {
        override suspend fun beforeOutboundData() = inner.beforeOutboundData()
        override suspend fun onInboundData(digestAfterCell: ByteArray) = inner.onInboundData(digestAfterCell)
        override suspend fun onInboundSendme() = inner.onInboundSendme()
    }

    /** Switch to prop324 Vegas windows (typically after ntor-v3 CC_FIELD_RESPONSE). */
    fun enableCongestionControl(sendmeInc: Int) {
        congestionSendmeInc = sendmeInc
        flow = CcWindows(CongestionControl.fromNegotiatedSendmeInc(sendmeInc))
    }

    init {
        scope.launch {
            try {
                while (true) {
                    val cell = inbound.receive()
                    when (cell.command) {
                        CellCommand.CREATED2, CellCommand.CREATED_FAST, CellCommand.CREATED ->
                            created2.send(cell)
                        CellCommand.DESTROY -> {
                            val reason = cell.payload.firstOrNull()?.toInt()?.and(0xff) ?: -1
                            val err = IllegalStateException(
                                "circuit DESTROY reason=$reason (${destroyReasonName(reason)})",
                            )
                            System.err.println(err.message)
                            created2.close(err)
                            circuitRelay.close(err)
                            break
                        }
                        CellCommand.RELAY, CellCommand.RELAY_EARLY -> {
                            if (layers.hopCount == 0) continue
                            val decoded = layers.decryptRelay(cell.payload, cell.command.id)
                            if (decoded == null) {
                                System.err.println("circuit $id: undecryptable relay cell")
                                continue
                            }
                            val hopIndex = decoded.first
                            val relay = decoded.second
                            when {
                                relay.command == RelayCommand.PADDING_NEGOTIATED -> {
                                    introPad.onNegotiated(relay.data)
                                }
                                relay.command == RelayCommand.SENDME && relay.streamId == 0 -> {
                                    flow.onInboundSendme()
                                }
                                relay.command == RelayCommand.DATA -> {
                                    val dig = layers.inboundDigestAt(hopIndex)
                                    val sendmeBody = flow.onInboundData(dig)
                                    if (sendmeBody != null) {
                                        sendRelay(buildRelayCell(RelayCommand.SENDME, 0, sendmeBody))
                                    }
                                    val ch = streams[relay.streamId]
                                    if (ch != null) {
                                        ch.send(relay)
                                    } else if (halfEdges.acceptInbound(relay.streamId, isSendme = false, isData = true)) {
                                        // Delivered into half-closed accounting only.
                                    } else {
                                        circuitRelay.send(relay)
                                    }
                                }
                                relay.command == RelayCommand.SENDME && relay.streamId != 0 -> {
                                    val ch = streams[relay.streamId]
                                    if (ch != null) {
                                        ch.send(relay)
                                    } else {
                                        halfEdges.acceptInbound(relay.streamId, isSendme = true, isData = false)
                                    }
                                }
                                relay.command == RelayCommand.END && relay.streamId != 0 -> {
                                    halfEdges.remove(relay.streamId)
                                    val ch = streams.remove(relay.streamId)
                                    if (ch != null) ch.send(relay) else circuitRelay.send(relay)
                                }
                                else -> {
                                    val ch = streams[relay.streamId]
                                    if (ch != null) ch.send(relay) else circuitRelay.send(relay)
                                }
                            }
                        }
                        else -> System.err.println("circuit $id unexpected ${cell.command}")
                    }
                }
            } catch (_: Exception) {
                streams.values.forEach { it.close() }
            }
        }
    }

    suspend fun createFirstHop(guard: RouterStatus, keys: HopKeys) {
        val ed = keys.ed25519Identity ?: guard.ed25519Identity
        if (guard.supportsNtorV3() && ed != null) {
            createFirstHopNtorV3(guard, keys.ntorOnionKey, ed)
        } else {
            createFirstHopNtor(guard, keys.ntorOnionKey)
        }
    }

    /**
     * One-hop CREATE_FAST (directory circuits). Prefer ntor when onion keys are known.
     */
    suspend fun createFirstHopFast() {
        val (state, x) = org.kotlintor.crypto.CreateFast.clientBegin()
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        x.copyInto(payload)
        conn.send(Cell(id, CellCommand.CREATE_FAST, payload))
        val created = withTimeout(20_000) { created2.receive() }
        // CREATED_FAST arrives as CREATED_FAST command — also accept CREATED2 misuse
        val hs = when (created.command) {
            CellCommand.CREATED_FAST, CellCommand.CREATED2, CellCommand.CREATED ->
                created.payload.copyOfRange(0, 40)
            else -> error("expected CREATED_FAST, got ${created.command}")
        }
        val result = org.kotlintor.crypto.CreateFast.clientFinish(state, hs)
        lastHopKh = result.kh
        layers.addHop(HopCrypto.fromCreateFast(result))
    }

    /**
     * Prop364 CreateOnehop via CREATE2 (preferred over CREATE_FAST when peer Link supports it).
     */
    suspend fun createFirstHopOnehop() {
        // CC uses CC_FIELD_REQUEST only — FlowCtrl must NOT appear in SUBPROTO (tor-spec allowlist is Relay=6).
        val cm = if (requestCongestionControl) {
            CircuitExtensions.ccRequest()
        } else {
            CircuitExtensions.encode(emptyList())
        }
        val (state, handshake) = org.kotlintor.crypto.CreateOnehop.clientBegin(cm)
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        val body = buildCreate2Payload(org.kotlintor.crypto.CreateOnehop.HTYPE, handshake)
        body.copyInto(payload)
        conn.send(Cell(id, CellCommand.CREATE2, payload))
        val created = withTimeout(20_000) { created2.receive() }
        val serverHs = parseCreated2Payload(created.payload)
        val result = org.kotlintor.crypto.CreateOnehop.clientFinish(state, serverHs, keystreamLen = 92)
        lastHopKh = HopCrypto.khFromNtorV3Keystream(result.keystream)
        layers.addHop(HopCrypto.fromNtorV3Keystream(result.keystream))
        CircuitExtensions.sendmeIncOrNull(result.serverMessage)?.let { enableCongestionControl(it) }
    }

    private suspend fun createFirstHopNtor(guard: RouterStatus, ntorKey: ByteArray) {
        val state = Ntor.clientHandshake(guard.identity, ntorKey)
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        val body = buildCreate2Payload(Ntor.HTYPE, state.handshake)
        body.copyInto(payload)
        conn.send(Cell(id, CellCommand.CREATE2, payload))
        val created = withTimeout(20_000) { created2.receive() }
        val serverHs = parseCreated2Payload(created.payload)
        val result = Ntor.clientFinish(state, guard.identity, ntorKey, serverHs)
        lastHopKh = result.kh
        layers.addHop(HopCrypto.fromNtor(result))
    }

    private suspend fun createFirstHopNtorV3(guard: RouterStatus, ntorKey: ByteArray, ed25519Id: ByteArray) {
        val relay = NtorV3.PublicKey(ed25519Id, ntorKey)
        val wantCgo = requestCgo && guard.supportsSubprotoNegotiate() && guard.supportsCgo()
        val cm = clientHandshakeExtensions(guard, wantCgo)
        val ksLen = if (wantCgo) 160 else 92
        val (state, handshake) = NtorV3.clientBegin(relay, cm)
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        val body = buildCreate2Payload(NtorV3.HTYPE, handshake)
        body.copyInto(payload)
        conn.send(Cell(id, CellCommand.CREATE2, payload))
        val created = withTimeout(20_000) { created2.receive() }
        val serverHs = parseCreated2Payload(created.payload)
        val result = NtorV3.clientFinish(state, serverHs, keystreamLen = ksLen)
        if (wantCgo && result.keystream.size >= 160) {
            cgoNegotiated = true
            lastHopKh = ByteArray(20)
            layers.addCgoHop(
                CgoClientHopLayer.fromSeeds(
                    result.keystream.copyOfRange(0, 80),
                    result.keystream.copyOfRange(80, 160),
                ),
            )
        } else {
            lastHopKh = HopCrypto.khFromNtorV3Keystream(result.keystream)
            layers.addHop(HopCrypto.fromNtorV3Keystream(result.keystream))
        }
        CircuitExtensions.sendmeIncOrNull(result.serverMessage)?.let { enableCongestionControl(it) }
    }

    suspend fun extend(router: RouterStatus, keys: HopKeys) {
        val ed = keys.ed25519Identity ?: router.ed25519Identity
        val addr = InetAddress.getByName(router.ip).address
        val ls = buildList {
            add(ipv4LinkSpecifier(addr, router.orPort))
            add(legacyIdLinkSpecifier(router.identity))
            ed?.let { add(ed25519IdLinkSpecifier(it)) }
        }
        if (router.supportsNtorV3() && ed != null) {
            extendNtorV3(router, keys.ntorOnionKey, ed, ls)
        } else {
            extendNtor(router, keys, ls)
        }
    }

    private suspend fun extendNtor(router: RouterStatus, keys: HopKeys, ls: List<ByteArray>) {
        val state = Ntor.clientHandshake(router.identity, keys.ntorOnionKey)
        val data = buildExtend2Data(ls, Ntor.HTYPE, state.handshake)
        sendRelay(buildRelayCell(RelayCommand.EXTEND2, 0, data), early = true)
        val serverHs = awaitExtended2Handshake()
        val result = Ntor.clientFinish(state, router.identity, keys.ntorOnionKey, serverHs)
        lastHopKh = result.kh
        layers.addHop(HopCrypto.fromNtor(result))
    }

    private suspend fun extendNtorV3(
        router: RouterStatus,
        ntorKey: ByteArray,
        ed25519Id: ByteArray,
        ls: List<ByteArray>,
    ) {
        val relay = NtorV3.PublicKey(ed25519Id, ntorKey)
        // CGO is all-or-nothing: SUBPROTO Relay=6 only when hop has Relay=5+6 (tor-spec).
        val hopCgo = router.supportsSubprotoNegotiate() && router.supportsCgo()
        val wantCgo = requestCgo && hopCgo && (layers.hopCount == 0 || cgoNegotiated)
        require(!cgoNegotiated || wantCgo) { "CGO circuit cannot extend through non-CGO hop" }
        val cm = clientHandshakeExtensions(router, wantCgo)
        val ksLen = if (wantCgo) 160 else 92
        val (state, handshake) = NtorV3.clientBegin(relay, cm)
        val data = buildExtend2Data(ls, NtorV3.HTYPE, handshake)
        sendRelay(buildRelayCell(RelayCommand.EXTEND2, 0, data), early = true)
        val serverHs = awaitExtended2Handshake()
        val result = NtorV3.clientFinish(state, serverHs, keystreamLen = ksLen)
        if (wantCgo && result.keystream.size >= 160) {
            cgoNegotiated = true
            lastHopKh = ByteArray(20)
            layers.addCgoHop(
                CgoClientHopLayer.fromSeeds(
                    result.keystream.copyOfRange(0, 80),
                    result.keystream.copyOfRange(80, 160),
                ),
            )
        } else {
            lastHopKh = HopCrypto.khFromNtorV3Keystream(result.keystream)
            layers.addHop(HopCrypto.fromNtorV3Keystream(result.keystream))
        }
        // Only enable CC from the last negotiated hop (exit).
        CircuitExtensions.sendmeIncOrNull(result.serverMessage)?.let { enableCongestionControl(it) }
    }

    /**
     * ntor-v3 client extensions per tor-spec:
     * - CC via empty [CC_FIELD_REQUEST] when hop advertises FlowCtrl=2
     * - CGO via SUBPROTO body `[0x02,0x06]` (Relay=6) only; never put FlowCtrl in SUBPROTO
     */
    private fun clientHandshakeExtensions(
        hop: RouterStatus,
        wantCgo: Boolean = requestCgo && hop.supportsSubprotoNegotiate() && hop.supportsCgo(),
    ): ByteArray {
        val exts = mutableListOf<CircuitExtensions.Ext>()
        if (requestCongestionControl && hop.supportsFlowCtrl2()) {
            exts += CircuitExtensions.Ext(CircuitExtensions.CC_FIELD_REQUEST, ByteArray(0))
        }
        if (wantCgo) {
            exts += CircuitExtensions.cgoSubprotoRequest()
        }
        return if (exts.isEmpty()) NtorV3.emptyExtensions() else CircuitExtensions.encode(exts)
    }

    private suspend fun awaitExtended2Handshake(): ByteArray {
        val extended = withTimeout(60_000) {
            while (true) {
                val r = circuitRelay.receive()
                when (r.command) {
                    RelayCommand.EXTENDED2 -> return@withTimeout r
                    RelayCommand.TRUNCATED ->
                        error("TRUNCATED while extending: ${r.data.firstOrNull()}")
                    else ->
                        System.err.println("extend: ignoring relay cmd=${r.command} len=${r.length}")
                }
            }
            error("unreachable")
        }
        val hlen = ((extended.data[0].toInt() and 0xff) shl 8) or (extended.data[1].toInt() and 0xff)
        return extended.data.copyOfRange(2, 2 + hlen)
    }

    /**
     * Open a stream to [host]:[port].
     * When [optimisticData] is true, returns immediately after BEGIN (tor optimistic data);
     * early DATA may race CONNECTED on the wire.
     */
    suspend fun openStream(host: String, port: Int, optimisticData: Boolean = false): TorStream {
        val streamId = mutex.withLock { nextStreamId++ }
        val ch = Channel<RelayCell>(Channel.UNLIMITED)
        streams[streamId] = ch
        edgeStreams.open(id, streamId, "$host:$port", isExit = false)
        noteStreamOpened()
        markPathBiasUseAttempted()
        sendRelay(buildRelayCell(RelayCommand.BEGIN, streamId, buildBeginPayload(host, port)))
        if (!optimisticData) {
            awaitConnected(ch)
            edgeStreams.markOpen(id, streamId)
            markPathBiasUseSucceeded()
        } else {
            edgeStreams.markOpen(id, streamId)
        }
        return TorStream(streamId, this, ch)
    }

    /** DNS RESOLVE (hostname → IPv4/IPv6 via exit). */
    suspend fun resolve(hostname: String): List<String> {
        val streamId = mutex.withLock { nextStreamId++ }
        val ch = Channel<RelayCell>(Channel.UNLIMITED)
        streams[streamId] = ch
        noteStreamOpened()
        val q = hostname.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        sendRelay(buildRelayCell(RelayCommand.RESOLVE, streamId, q))
        return withTimeout(30_000) {
            while (true) {
                val r = ch.receive()
                when (r.command) {
                    RelayCommand.RESOLVED -> {
                        streams.remove(streamId)?.close()
                        return@withTimeout parseResolved(r.data)
                    }
                    RelayCommand.END -> {
                        streams.remove(streamId)?.close()
                        error("RESOLVE END: ${r.data.firstOrNull()}")
                    }
                    else -> Unit
                }
            }
            error("unreachable")
        }
    }

    private fun parseResolved(data: ByteArray): List<String> {
        val out = mutableListOf<String>()
        var i = 0
        while (i + 2 <= data.size) {
            val type = data[i].toInt() and 0xff
            val len = data[i + 1].toInt() and 0xff
            i += 2
            if (i + len > data.size) break
            val body = data.copyOfRange(i, i + len)
            i += len
            // TTL 4 bytes may follow
            if (i + 4 <= data.size) i += 4
            when (type) {
                0x00 -> break // empty / error terminator variants
                0x04 -> if (body.size == 4) {
                    out += body.joinToString(".") { (it.toInt() and 0xff).toString() }
                }
                0x06 -> if (body.size == 16) {
                    out += java.net.InetAddress.getByAddress(body).hostAddress
                }
                0xF0 -> Unit // error
            }
        }
        return out
    }

    /** Directory stream to the last hop (BEGIN_DIR). */
    suspend fun openDirStream(): TorStream {
        val streamId = mutex.withLock { nextStreamId++ }
        val ch = Channel<RelayCell>(Channel.UNLIMITED)
        streams[streamId] = ch
        noteStreamOpened()
        sendRelay(buildRelayCell(RelayCommand.BEGIN_DIR, streamId, ByteArray(0)))
        awaitConnected(ch)
        return TorStream(streamId, this, ch)
    }

    /**
     * ESTABLISH_RENDEZVOUS on this circuit (typically ending at the RP).
     * Returns the 20-byte rendezvous cookie.
     */
    suspend fun establishRendezvous(cookie: ByteArray = SecureRandomSource.nextBytes(20)): ByteArray {
        require(cookie.size == 20)
        sendRelay(buildRelayCell(RelayCommand.ESTABLISH_RENDEZVOUS, 0, cookie))
        withTimeout(60_000) {
            while (true) {
                val r = circuitRelay.receive()
                when (r.command) {
                    RelayCommand.RENDEZVOUS_ESTABLISHED -> return@withTimeout
                    RelayCommand.TRUNCATED ->
                        error("TRUNCATED during ESTABLISH_RENDEZVOUS: ${r.data.firstOrNull()}")
                    else ->
                        System.err.println("rend-establish: ignoring ${r.command}")
                }
            }
        }
        return cookie
    }

    /** Send INTRODUCE1 (stream_id=0) and wait for INTRODUCE_ACK success. */
    suspend fun sendIntroduce1(payload: ByteArray) {
        if (circuitPaddingEnabled && circuitPaddingNegotiate) {
            // Best-effort: negotiate padding with middle before INTRODUCE1 (prop302).
            runCatching { introPad.negotiateStart() }
        }
        sendRelay(buildRelayCell(RelayCommand.INTRODUCE1, 0, payload))
        if (circuitPaddingEnabled) {
            introPad.onIntroduce1Sent()
            // Non-blocking best-effort: flush DROP cells while awaiting ACK (prop302).
            runCatching { introPad.flushPendingDrops() }
        }
        withTimeout(45_000) {
            while (true) {
                val r = circuitRelay.receive()
                when (r.command) {
                    RelayCommand.INTRODUCE_ACK -> {
                        val status = if (r.data.size >= 2) {
                            ((r.data[0].toInt() and 0xff) shl 8) or (r.data[1].toInt() and 0xff)
                        } else {
                            -1
                        }
                        check(status == 0) { "INTRODUCE_ACK failure status=$status" }
                        return@withTimeout
                    }
                    RelayCommand.PADDING_NEGOTIATED -> introPad.onNegotiated(r.data)
                    RelayCommand.TRUNCATED ->
                        error("TRUNCATED during INTRODUCE1: ${r.data.firstOrNull()}")
                    else ->
                        System.err.println("introduce1: ignoring ${r.command}")
                }
            }
        }
    }

    /** Wait for RENDEZVOUS2 and return HANDSHAKE_INFO. */
    suspend fun awaitRendezvous2(): ByteArray = withTimeout(90_000) {
        while (true) {
            val r = circuitRelay.receive()
            when (r.command) {
                RelayCommand.RENDEZVOUS2 -> return@withTimeout r.data
                RelayCommand.TRUNCATED ->
                    error("TRUNCATED waiting for RENDEZVOUS2: ${r.data.firstOrNull()}")
                else ->
                    System.err.println("rendezvous2: ignoring ${r.command}")
            }
        }
        error("unreachable")
    }

    /** Attach the virtual HS hop (AES-256 + SHA3-256) after a successful rendezvous. */
    fun addHsHop(keys: HsNtor.HopKeyMaterial) {
        layers.addHop(HopCrypto.fromHsNtor(keys))
    }

    /** ESTABLISH_INTRO at the last hop; wait for INTRO_ESTABLISHED. */
    suspend fun establishIntro(authPublic: ByteArray, authPrivate: ByteArray) {
        val kh = lastHopKh ?: error("no KH on circuit")
        val body = org.kotlintor.hs.HsEstablishIntro.build(authPublic, authPrivate, kh)
        sendRelay(buildRelayCell(RelayCommand.ESTABLISH_INTRO, 0, body))
        withTimeout(45_000) {
            while (true) {
                val r = circuitRelay.receive()
                when (r.command) {
                    RelayCommand.INTRO_ESTABLISHED -> return@withTimeout
                    RelayCommand.TRUNCATED ->
                        error("TRUNCATED during ESTABLISH_INTRO: ${r.data.firstOrNull()}")
                    else ->
                        System.err.println("establish-intro: ignoring ${r.command}")
                }
            }
        }
    }

    /**
     * Wait for INTRODUCE2 on an established intro circuit; return relay payload.
     * No timeout by default — host intro circuits idle for long periods.
     */
    suspend fun awaitIntroduce2(timeoutMs: Long = Long.MAX_VALUE): ByteArray {
        suspend fun waitOnce(): ByteArray {
            while (true) {
                val r = circuitRelay.receive()
                when (r.command) {
                    RelayCommand.INTRODUCE2 -> return r.data
                    RelayCommand.TRUNCATED ->
                        error("TRUNCATED waiting for INTRODUCE2: ${r.data.firstOrNull()}")
                    else ->
                        System.err.println("introduce2-wait: ignoring ${r.command}")
                }
            }
        }
        return if (timeoutMs == Long.MAX_VALUE) waitOnce()
        else withTimeout(timeoutMs) { waitOnce() }
    }

    /** Send RENDEZVOUS1 (cookie ‖ handshake_info) toward the rendezvous point. */
    suspend fun sendRendezvous1(cookie: ByteArray, handshakeInfo: ByteArray) {
        require(cookie.size == 20)
        sendRelay(buildRelayCell(RelayCommand.RENDEZVOUS1, 0, cookie + handshakeInfo))
    }

    data class AcceptedBegin(val stream: TorStream, val address: String, val port: Int)

    /**
     * After the virtual HS hop is attached, wait for an inbound BEGIN and reply CONNECTED.
     */
    suspend fun acceptBegin(timeoutMs: Long = 60_000): AcceptedBegin = withTimeout(timeoutMs) {
        while (true) {
            val r = circuitRelay.receive()
            when (r.command) {
                RelayCommand.BEGIN -> {
                    val (addr, port) = parseBeginPayload(r.data)
                    val ch = Channel<RelayCell>(Channel.UNLIMITED)
                    streams[r.streamId] = ch
                    sendRelay(buildRelayCell(RelayCommand.CONNECTED, r.streamId, ByteArray(0)))
                    return@withTimeout AcceptedBegin(
                        TorStream(r.streamId, this@Circuit, ch),
                        addr,
                        port,
                    )
                }
                RelayCommand.TRUNCATED ->
                    error("TRUNCATED waiting for BEGIN: ${r.data.firstOrNull()}")
                else ->
                    System.err.println("accept-begin: ignoring ${r.command}")
            }
        }
        error("unreachable")
    }

    private suspend fun awaitConnected(ch: Channel<RelayCell>) {
        withTimeout(30_000) {
            while (true) {
                val r = ch.receive()
                when (r.command) {
                    RelayCommand.CONNECTED -> return@withTimeout
                    RelayCommand.END -> error("stream END before CONNECTED: ${r.data.firstOrNull()}")
                    else -> Unit
                }
            }
        }
    }

    internal suspend fun sendRelay(cell: RelayCell, early: Boolean = false) {
        val cellCmd = if (early) CellCommand.RELAY_EARLY else CellCommand.RELAY
        val payload = layers.encryptRelay(cell, cellCmd.id)
        conn.send(Cell(id, cellCmd, payload))
    }

    internal suspend fun sendData(streamId: Int, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val n = minOf(498, data.size - offset)
            flow.beforeOutboundData()
            sendRelay(buildRelayCell(RelayCommand.DATA, streamId, data.copyOfRange(offset, offset + n)))
            offset += n
        }
    }

    internal fun closeStream(streamId: Int) {
        streams.remove(streamId)?.close()
        // C Tor: keep half_edge until peer END / windows drain.
        halfEdges.add(
            HalfEdge(
                streamId = streamId,
                sendmesPending = 10,
                dataPending = 1000,
                endAckExpectedUsec = System.nanoTime() / 1000 + 60_000_000,
                usedCcontrol = congestionSendmeInc != null,
            ),
        )
        if (streams.isEmpty()) {
            unusedSinceMs = System.currentTimeMillis()
        }
    }

    private fun markPathBiasUseAttempted() {
        val t = pathBiasTracker ?: return
        val g = pathBiasGuardFp ?: return
        t.markUseAttempted(id, g)
    }

    private fun markPathBiasUseSucceeded() {
        val t = pathBiasTracker ?: return
        val g = pathBiasGuardFp ?: return
        t.markUseSucceeded(id, g)
    }

    private fun noteStreamOpened() {
        val now = System.currentTimeMillis()
        if (dirtySinceMs == null) dirtySinceMs = now
        unusedSinceMs = null
    }

    /**
     * True when the circuit is dirty (had streams) and has been unused longer than [unusedTimeoutMs]
     * (prop368 unused-circuit timeout lite).
     */
    fun isUnusedPast(unusedTimeoutMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        if (streams.isNotEmpty()) return false
        val since = unusedSinceMs ?: return false
        return nowMs - since >= unusedTimeoutMs
    }

    /** Refuse new streams after CircuitDirtyTimeout (prop368 dirty timeout lite). */
    fun isTooDirtyForAttach(dirtyTimeoutMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        val dirty = dirtySinceMs ?: return false
        return nowMs - dirty >= dirtyTimeoutMs
    }

    fun close() {
        conn.unregisterCircuit(id)
        streams.values.forEach { it.close() }
        streams.clear()
        unusedSinceMs = System.currentTimeMillis()
    }
}

private fun destroyReasonName(code: Int): String =
    org.kotlintor.cell.Reasons.circuitEndToControl(code)

class TorStream(
    val streamId: Int,
    private val circuit: Circuit,
    private val inbound: Channel<RelayCell>,
) {
    suspend fun write(data: ByteArray) = circuit.sendData(streamId, data)

    suspend fun read(): ByteArray {
        while (true) {
            val cell = inbound.receive()
            when (cell.command) {
                RelayCommand.DATA -> return cell.data
                RelayCommand.END -> return ByteArray(0)
                else -> Unit
            }
        }
    }

    /** Read until END or [idleTimeoutMs] without data after seeing headers/body. */
    suspend fun readHttpResponse(maxBytes: Int = 512 * 1024): ByteArray {
        val out = ArrayList<Byte>()
        while (out.size < maxBytes) {
            val chunk = try {
                withTimeout(30_000) { read() }
            } catch (_: Exception) {
                break
            }
            if (chunk.isEmpty()) break
            for (b in chunk) out += b
            // Heuristic: HTTP response complete when Content-Length satisfied or blank line + body.
            val text = out.toByteArray().decodeToString()
            val headerEnd = text.indexOf("\r\n\r\n")
            if (headerEnd >= 0) {
                val headers = text.substring(0, headerEnd)
                val cl = Regex("(?i)Content-Length:\\s*(\\d+)").find(headers)?.groupValues?.get(1)?.toIntOrNull()
                if (cl != null && out.size >= headerEnd + 4 + cl) break
                if (cl == null && headers.contains("Transfer-Encoding: chunked", ignoreCase = true)) {
                    if (text.contains("\r\n0\r\n\r\n")) break
                }
            }
        }
        return out.toByteArray()
    }

    suspend fun close() {
        circuit.sendRelay(buildRelayCell(RelayCommand.END, streamId, byteArrayOf(1)))
        circuit.closeStream(streamId)
    }
}

class CircuitManager(
    private val scope: CoroutineScope,
    private val onCircEvent: (String) -> Unit = {},
    /** Optional first-hop TCP dialer (PT SOCKS → bridge). */
    private val firstHopDialer: (suspend (host: String, port: Int) -> java.net.Socket)? = null,
    /** CircuitBuildTimeout (ms). Default 60s. */
    private val circuitBuildTimeoutMs: Long = 60_000,
    /** When true, blend learned CBT quantile with configured timeout. */
    private val learnCircuitBuildTimeout: Boolean = true,
    pathBiasOptions: org.kotlintor.config.PathBiasOptions = org.kotlintor.config.PathBiasOptions.DEFAULT,
) {
    private val connections = mutableMapOf<String, OrConnection>()
    private val open = mutableMapOf<Long, CircuitPath>()
    val pathBias: PathBiasTracker = PathBiasTracker(pathBiasOptions)
    val circuitBuildTimeout: CircuitBuildTimeout = CircuitBuildTimeout()
    private var lastConsensusParams: Map<String, Long> = emptyMap()
    /** Preferred Schedulers= list applied to new OR connections. */
    var schedulerPreference: List<org.kotlintor.link.SchedulerType> =
        listOf(org.kotlintor.link.SchedulerType.KIST, org.kotlintor.link.SchedulerType.VANILLA)
    /** CircuitPadding torrc (prop302 negotiate). */
    var circuitPaddingEnabled: Boolean = true
    /** ConnectionPadding / ReducedPadding. */
    var connectionPaddingEnabled: Boolean = true
    var reducedChannelPadding: Boolean = false
    /** OutboundBindAddressOR applied to new OR sockets. */
    var outboundBindOr: String? = null
    /** ConstrainedSockets buffer size; null disables. */
    var constrainedSockSize: Int? = null

    fun applyConsensusParams(params: Map<String, Long>) {
        lastConsensusParams = params
        connections.values.forEach { it.applyConsensusParams(params) }
    }

    private fun effectiveTimeoutMs(): Long {
        if (!learnCircuitBuildTimeout) return circuitBuildTimeoutMs
        val learned = circuitBuildTimeout.timeoutMs()
        // Prefer the tighter of configured and learned once enough samples exist.
        return if (circuitBuildTimeout.sampleCount() >= 100) {
            minOf(circuitBuildTimeoutMs, learned)
        } else {
            circuitBuildTimeoutMs
        }
    }

    fun circuitStatusLines(): List<String> =
        open.entries.map { (id, path) ->
            "$id BUILT ${path.guard.fingerprintHex}=${path.guard.nickname}," +
                "${path.middle.fingerprintHex}=${path.middle.nickname}," +
                "${path.exit.fingerprintHex}=${path.exit.nickname} PURPOSE=GENERAL"
        }

    suspend fun buildCircuit(
        path: CircuitPath,
        hopKeys: Map<String, HopKeys>,
    ): Circuit = withTimeout(effectiveTimeoutMs()) {
        buildCircuitInner(path, hopKeys)
    }

    private suspend fun buildCircuitInner(
        path: CircuitPath,
        hopKeys: Map<String, HopKeys>,
    ): Circuit {
        val guardKeys = hopKeys[path.guard.fingerprintHex] ?: error("missing keys for guard")
        val middleKeys = hopKeys[path.middle.fingerprintHex] ?: error("missing keys for middle")
        val exitKeys = hopKeys[path.exit.fingerprintHex] ?: error("missing keys for exit")
        val guardFp = path.guard.fingerprintHex
        val started = System.currentTimeMillis()

        val key = "${path.guard.ip}:${path.guard.orPort}"
        val conn = connections.getOrPut(key) {
            val dial = firstHopDialer
            OrConnection(
                path.guard.ip,
                path.guard.orPort,
                scope,
                dialer = if (dial != null) {
                    { dial(path.guard.ip, path.guard.orPort) }
                } else {
                    null
                },
                bindLocalHost = outboundBindOr,
                constrainedSockSize = constrainedSockSize,
            ).also {
                it.writeBudget.type = org.kotlintor.link.ChannelScheduler.select(schedulerPreference)
                it.channelPadding.enabled = connectionPaddingEnabled
                it.connect(expectedIdentityHex = path.guard.fingerprintHex)
                if (lastConsensusParams.isNotEmpty()) it.applyConsensusParams(lastConsensusParams)
                if (reducedChannelPadding) {
                    it.channelPadding.params =
                        org.kotlintor.link.ChannelPaddingParams.fromConsensus(
                            lastConsensusParams.mapValues { e -> e.value.toInt() },
                            reduced = true,
                        )
                }
            }
        }
        val circId = OrConnection.newCircId()
        pathBias.markBuildAttempted(circId, guardFp)
        RepHist.noteCreate(guardFp)
        onCircEvent("CIRC $circId LAUNCHED PURPOSE=GENERAL")
        val inbound = conn.registerCircuit(circId)
        val circ = Circuit(circId, conn, scope, inbound)
        circ.circuitPaddingEnabled = circuitPaddingEnabled
        CircuitList.put(circ.meta)
        try {
            // CGO only when explicitly requested AND every hop advertises Relay=5+6.
            val pathCgo = circ.requestCgo &&
                path.guard.supportsSubprotoNegotiate() && path.guard.supportsCgo() &&
                path.middle.supportsSubprotoNegotiate() && path.middle.supportsCgo() &&
                path.exit.supportsSubprotoNegotiate() && path.exit.supportsCgo()
            circ.requestCgo = pathCgo
            println(
                "creating hop1 ${path.guard.nickname} (ntor-v3=${path.guard.supportsNtorV3()} " +
                    "cc=${path.guard.supportsFlowCtrl2()} cgo=$pathCgo)...",
            )
            circ.createFirstHop(path.guard, guardKeys)
            println("hop1 OK; extending to ${path.middle.nickname} (ntor-v3=${path.middle.supportsNtorV3()})...")
            circ.extend(path.middle, middleKeys)
            println("hop2 OK; extending to ${path.exit.nickname}...")
            circ.extend(path.exit, exitKeys)
            println("hop3 OK")
            val elapsed = System.currentTimeMillis() - started
            pathBias.markBuildSucceeded(circId, guardFp)
            circuitBuildTimeout.addSuccess(elapsed)
            RepHist.noteSuccess(guardFp)
            circ.pathBiasTracker = pathBias
            circ.pathBiasGuardFp = guardFp
            open[circId] = path
            onCircEvent(
                "CIRC $circId BUILT ${path.guard.nickname},${path.middle.nickname},${path.exit.nickname} PURPOSE=GENERAL",
            )
            return circ
        } catch (e: Exception) {
            pathBias.forgetCircuit(circId)
            RepHist.noteFailure(guardFp)
            CircuitList.remove(circId)
            conn.unregisterCircuit(circId)
            throw e
        }
    }

    /**
     * One-hop directory circuit (prop364 CreateOnehop, falling back to CREATE_FAST).
     */
    suspend fun buildOneHopDirCircuit(
        relay: RouterStatus,
        useCreateOnehop: Boolean = true,
    ): Circuit {
        val key = "${relay.ip}:${relay.orPort}"
        val conn = connections.getOrPut(key) {
            OrConnection(
                relay.ip,
                relay.orPort,
                scope,
                bindLocalHost = outboundBindOr,
                constrainedSockSize = constrainedSockSize,
            ).also {
                it.writeBudget.type = org.kotlintor.link.ChannelScheduler.select(schedulerPreference)
                it.connect(expectedIdentityHex = relay.fingerprintHex)
                if (lastConsensusParams.isNotEmpty()) it.applyConsensusParams(lastConsensusParams)
            }
        }
        val circId = OrConnection.newCircId()
        onCircEvent("CIRC $circId LAUNCHED PURPOSE=DIR_FETCH")
        val inbound = conn.registerCircuit(circId)
        val circ = Circuit(circId, conn, scope, inbound)
        circ.meta = CircuitMeta(CircuitKind.Origin(circId, org.kotlintor.cell.CircuitPurpose.DIR_FETCH, pathLength = 1))
        CircuitList.put(circ.meta)
        if (useCreateOnehop) {
            circ.createFirstHopOnehop()
        } else {
            circ.createFirstHopFast()
        }
        onCircEvent("CIRC $circId BUILT ${relay.nickname} PURPOSE=DIR_FETCH")
        return circ
    }
}
