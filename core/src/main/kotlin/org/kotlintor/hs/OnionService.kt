package org.kotlintor.hs

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.kotlintor.cell.RelayCommand
import org.kotlintor.circuit.Circuit
import org.kotlintor.circuit.HopKeys
import org.kotlintor.circuit.TorStream
import org.kotlintor.circuit.buildRelayCell
import org.kotlintor.config.HiddenServiceConfig
import org.kotlintor.config.HiddenServicePort
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.RouterStatus
import org.kotlintor.path.CircuitPath
import org.kotlintor.util.toHex
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path

/**
 * Onion service v3 address encoding + host lifecycle
 * (ESTABLISH_INTRO + descriptor encrypt/publish).
 */
object OnionAddressV3 {
    private const val VERSION: Byte = 0x03

    fun encode(publicKey: ByteArray): String {
        require(publicKey.size == 32)
        val checksumInput = ".onion checksum".toByteArray() + publicKey + byteArrayOf(VERSION)
        val checksum = Digests.sha3_256(checksumInput).copyOfRange(0, 2)
        val raw = publicKey + checksum + byteArrayOf(VERSION)
        return base32(raw) + ".onion"
    }

    fun decode(address: String): ByteArray {
        val onion = address.lowercase().removeSuffix(".onion")
        val raw = base32Decode(onion)
        require(raw.size == 35) { "invalid v3 onion length" }
        require(raw[34] == VERSION)
        val pubkey = raw.copyOfRange(0, 32)
        val checksum = raw.copyOfRange(32, 34)
        val expect = Digests.sha3_256(".onion checksum".toByteArray() + pubkey + byteArrayOf(VERSION))
            .copyOfRange(0, 2)
        require(checksum.contentEquals(expect)) { "onion checksum mismatch" }
        return pubkey
    }

    private fun base32(data: ByteArray): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val out = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                out.append(alphabet[(buffer shr (bitsLeft - 5)) and 31])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            out.append(alphabet[(buffer shl (5 - bitsLeft)) and 31])
        }
        return out.toString()
    }

    private fun base32Decode(s: String): ByteArray {
        val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        val map = IntArray(128) { -1 }
        for (i in alphabet.indices) map[alphabet[i].code] = i
        val out = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (ch in s) {
            val v = map.getOrElse(ch.code) { -1 }
            require(v >= 0) { "invalid base32" }
            buffer = (buffer shl 5) or v
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out += ((buffer shr (bitsLeft - 8)) and 0xff).toByte()
                bitsLeft -= 8
            }
        }
        return out.toByteArray()
    }
}

data class IntroPointLive(
    val relay: RouterStatus,
    val authKey: Ed25519KeyPair,
    val encKey: org.kotlintor.crypto.X25519KeyPair,
    val circuit: Circuit,
    var listenJob: Job? = null,
    /** C Tor `hs_service_intro_point_t.replay_cache` for INTRODUCE2 ENCRYPTED. */
    val introduceReplayCache: ReplayCache = ReplayCache(),
)

data class OnionServiceInstance(
    val config: HiddenServiceConfig,
    val address: String,
    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val introPoints: MutableList<IntroPointLive> = mutableListOf(),
    var lastDescriptor: String? = null,
    var blindedPublic: ByteArray? = null,
    var period: HsTimePeriod? = null,
    /** Active prop327 PoW seed (C) while defenses enabled. */
    var powSeed: ByteArray? = null,
    val authorizedClients: MutableList<HsClientAuth.ClientCred> = mutableListOf(),
    val introTable: HsIntroPointTable = HsIntroPointTable(),
)

class OnionServiceManager(
    private val config: TorConfig,
    private val scope: CoroutineScope,
) {
    private val running = mutableListOf<OnionServiceInstance>()
    private var publishJob: Job? = null
    private val descriptorCache = HsCache()

    var buildCircuit: (suspend (CircuitPath, Map<String, HopKeys>) -> Circuit)? = null
    var ensureHopKeys: (suspend (String) -> HopKeys)? = null
    var selectEndingAt: ((List<RouterStatus>, RouterStatus) -> CircuitPath)? = null
    var consensus: (() -> Consensus?)? = null
    var publishDescriptor: (suspend (String, ByteArray) -> Int)? = null
    /** Optional HS_DESC control event sink (TorDaemon → ControlServer). */
    var emitHsDesc: ((String) -> Unit)? = null

    fun startAll() {
        HsSys.init(config)
        for (hs in config.hiddenServices) {
            running += startOne(hs)
        }
        publishJob = scope.launch {
            for (inst in running.toList()) {
                runCatching {
                    establishIntroPoints(inst, n = inst.config.numIntroductionPoints.coerceIn(1, 20))
                    publish(inst)
                }.onFailure {
                    System.err.println("HS host ${inst.address}: ${it.message}")
                }
            }
        }
    }

    fun startOne(hs: HiddenServiceConfig): OnionServiceInstance {
        Files.createDirectories(hs.directory)
        val keyFile = hs.directory.resolve("hs_ed25519_secret_key")
        val pubFile = hs.directory.resolve("hs_ed25519_public_key")
        val hostname = hs.directory.resolve("hostname")
        val kp = if (Files.exists(keyFile) && Files.exists(pubFile)) {
            Ed25519KeyPair(Files.readAllBytes(keyFile), Files.readAllBytes(pubFile))
        } else {
            Ed25519Keys.generate().also {
                Files.write(keyFile, it.privateKey)
                Files.write(pubFile, it.publicKey)
            }
        }
        val address = OnionAddressV3.encode(kp.publicKey)
        Files.writeString(hostname, address + "\n")
        println("HiddenService $address dir=${hs.directory}")
        return OnionServiceInstance(hs, address, kp.publicKey, kp.privateKey)
    }

    suspend fun establishIntroPoints(inst: OnionServiceInstance, n: Int = 3) {
        val build = buildCircuit ?: error("OnionServiceManager.buildCircuit not wired")
        val ensure = ensureHopKeys ?: error("OnionServiceManager.ensureHopKeys not wired")
        val select = selectEndingAt ?: error("OnionServiceManager.selectEndingAt not wired")
        val cons = consensus?.invoke() ?: error("no consensus for HS host")
        val candidates = cons.relays
            .filter { it.isRunning && it.isFast && it.isStable }
            .shuffled()
            .take(n * 4)
        var established = 0
        for (relay in candidates) {
            if (established >= n) break
            try {
                val path = select(cons.relays, relay)
                val keys = mutableMapOf<String, HopKeys>()
                keys[path.guard.fingerprintHex] = ensure(path.guard.fingerprintHex)
                keys[path.middle.fingerprintHex] = ensure(path.middle.fingerprintHex)
                keys[path.exit.fingerprintHex] = ensure(path.exit.fingerprintHex)
                val circ = build(path, keys)
                val auth = Ed25519Keys.generate()
                val enc = Curve25519.generateKeyPair()
                val authHex = auth.publicKey.joinToString("") { "%02x".format(it) }
                inst.introTable.beginEstablish(authHex, circuitIdHint = circ.toString())
                circ.establishIntro(auth.publicKey, auth.privateKey)
                val live = IntroPointLive(relay, auth, enc, circ)
                inst.introPoints += live
                inst.introTable.noteEstablished(authHex)
                established++
                println(
                    "HS INTRO_ESTABLISHED at ${relay.nickname} " +
                        "auth=${auth.publicKey.toHex(8)}… for ${inst.address}",
                )
                live.listenJob = scope.launch {
                    listenIntroduce2(inst, live)
                }
            } catch (e: Exception) {
                System.err.println("HS intro ${relay.nickname}: ${e.message}")
            }
        }
        check(established > 0) { "failed to establish any introduction points" }
    }

    private suspend fun listenIntroduce2(inst: OnionServiceInstance, intro: IntroPointLive) {
        while (true) {
            try {
                val payload = intro.circuit.awaitIntroduce2()
                println("HS INTRODUCE2 on ${intro.relay.nickname} (${payload.size} bytes)")
                scope.launch {
                    runCatching { handleIntroduce2(inst, intro, payload) }
                        .onFailure { System.err.println("HS INTRODUCE2 handle: ${it.message}") }
                }
            } catch (e: Exception) {
                System.err.println("HS intro listen ${intro.relay.nickname}: ${e.message}")
                inst.introPoints.remove(intro)
                runCatching { intro.circuit.close() }
                // Replace the dead intro and republish when we still have a service.
                scope.launch {
                    runCatching {
                        establishIntroPoints(inst, n = 1)
                        if (inst.introPoints.isNotEmpty()) publish(inst)
                    }.onFailure {
                        System.err.println("HS intro re-establish: ${it.message}")
                    }
                }
                break
            }
        }
    }

    private suspend fun handleIntroduce2(
        inst: OnionServiceInstance,
        intro: IntroPointLive,
        payload: ByteArray,
    ) {
        val build = buildCircuit ?: error("buildCircuit not wired")
        val ensure = ensureHopKeys ?: error("ensureHopKeys not wired")
        val select = selectEndingAt ?: error("selectEndingAt not wired")
        val cons = consensus?.invoke() ?: error("no consensus")
        val period = inst.period ?: HsClient.timePeriodForConsensus(cons)
        val blinded = inst.blindedPublic ?: HsKeyBlind.blindPublicKey(inst.publicKey, period)
        val subcred = HsKeyBlind.subcredential(inst.publicKey, blinded)

        if (inst.config.maxIntroducesPerMin > 0) {
            val lim = HsIntroRateLimits.forService(inst.address, inst.config.maxIntroducesPerMin)
            if (!lim.tryAdmit()) error("INTRODUCE2 rate limited")
        }
        HsDosDefense.shared.applyConsensus(consensus?.invoke())
        if (!HsDosDefense.shared.noteIntroduce(inst.address)) {
            HsMetrics.noteIntroRejected()
            error("INTRODUCE2 DoS defense rejected")
        }
        HsMetrics.noteIntroReceived()
        val authHex = intro.authKey.publicKey.joinToString("") { "%02x".format(it) }
        inst.introTable.noteIntroduce(authHex)
        org.kotlintor.stats.HsStats.noteIntroduce2Cell()

        // INTRODUCE2 body == INTRODUCE1 body: LEGACY…N_EXTENSIONS | ENCRYPTED
        require(payload.size > 20 + 1 + 2 + 32 + 1) { "INTRODUCE2 too short" }
        var o = 20 // skip LEGACY_KEY_ID
        require(payload[o].toInt() and 0xff == 0x02) { "bad AUTH_KEY_TYPE" }
        o += 1
        val authLen = ((payload[o].toInt() and 0xff) shl 8) or (payload[o + 1].toInt() and 0xff)
        o += 2
        require(authLen == 32)
        val authKey = payload.copyOfRange(o, o + 32)
        o += 32
        require(authKey.contentEquals(intro.authKey.publicKey)) { "AUTH_KEY mismatch" }
        val nExt = payload[o].toInt() and 0xff
        o += 1
        // INTRODUCE1 outer extensions: EXT_FIELD_TYPE (1) + EXT_FIELD_LEN (1) + body
        var powOk = !inst.config.powEnabled
        repeat(nExt) {
            require(o + 2 <= payload.size) { "truncated INTRODUCE2 extension" }
            val type = payload[o].toInt() and 0xff
            val len = payload[o + 1].toInt() and 0xff
            val bodyStart = o + 2
            val bodyEnd = bodyStart + len
            require(bodyEnd <= payload.size) { "truncated INTRODUCE2 extension body" }
            if (type == HsPowProp327.EXT_POW_SOLUTION && len == HsPowProp327.SOLUTION_PAYLOAD_LEN) {
                val seed = inst.powSeed ?: error("PoW enabled but no seed published")
                val sol = HsPowProp327.Solution.parse(payload.copyOfRange(bodyStart, bodyEnd), seed)
                powOk = HsPowProp327.verifySolution(sol, blinded, minEffort = inst.config.powEffort)
                if (!powOk) error("INTRODUCE2 PoW verification failed")
            }
            o = bodyEnd
        }
        if (inst.config.powEnabled && !powOk) {
            error("INTRODUCE2 missing required PoW extension")
        }
        val header = payload.copyOfRange(0, o)
        val encrypted = payload.copyOfRange(o, payload.size)
        // C Tor hs_cell.c: replaycache on ENCRYPTED section before ntor decrypt.
        if (intro.introduceReplayCache.addAndTest(encrypted)) {
            error("INTRODUCE2 replay detected (duplicate ENCRYPTED section)")
        }
        val svc = HsNtor.serviceReceiveIntro(
            encPrivate = intro.encKey.privateKey,
            encPublic = intro.encKey.publicKey,
            authKey = intro.authKey.publicKey,
            subcredential = subcred,
            introHeader = header,
            encrypted = encrypted,
        )

        val links = LinkSpecifiers.parsePacked(svc.plaintext.rendLinkSpecifiers)
        val rendFp = links.legacyId?.let { LinkSpecifiers.fingerprintHex(it) }
            ?: error("rendezvous missing legacy id")
        val rendRouter = cons.relays.find { it.fingerprintHex == rendFp }
            ?: RouterStatus(
                nickname = "Rend",
                identity = links.legacyId!!,
                digest = ByteArray(20),
                publication = cons.validAfter,
                ip = links.ipv4?.let { InetAddress.getByAddress(it).hostAddress }
                    ?: error("rendezvous missing IPv4"),
                orPort = links.port ?: error("rendezvous missing ORPort"),
                dirPort = 0,
                flags = setOf("Running", "Fast", "V2Dir"),
                version = null,
                proto = emptyMap(),
                bandwidth = 1,
                ed25519Identity = links.ed25519Id,
            )
        val known = cons.relays.mapTo(HashSet()) { it.fingerprintHex }
        val pathRelays = if (rendFp in known) cons.relays else cons.relays + rendRouter
        val path = select(pathRelays, rendRouter)
        val keys = mutableMapOf<String, HopKeys>()
        keys[path.guard.fingerprintHex] = ensure(path.guard.fingerprintHex)
        keys[path.middle.fingerprintHex] = ensure(path.middle.fingerprintHex)
        keys[path.exit.fingerprintHex] = HopKeys(svc.plaintext.rendOnionKey, links.ed25519Id)
        val rendCirc = build(path, keys)
        try {
            rendCirc.sendRendezvous1(svc.plaintext.rendezvousCookie, svc.handshakeInfo)
            rendCirc.addHsHop(svc.hopKeys)
            org.kotlintor.stats.HsStats.noteServiceRendezvousLaunch()
            println("HS RENDEZVOUS1 sent via ${rendRouter.nickname}; waiting BEGIN…")
            val accepted = rendCirc.acceptBegin(timeoutMs = 60_000)
            println(
                "HS BEGIN stream_id=${accepted.stream.streamId} " +
                    "virt=${accepted.address}:${accepted.port}; proxying",
            )
            proxyStream(inst, accepted.stream, accepted.port)
        } catch (e: Exception) {
            rendCirc.close()
            throw e
        }
    }

    private suspend fun proxyStream(inst: OnionServiceInstance, stream: TorStream, virtualPort: Int) {
        val mapped = inst.config.ports.firstOrNull { it.virtualPort == virtualPort }
            ?: inst.config.ports.firstOrNull()
        val target = mapped?.target ?: "127.0.0.1:$virtualPort"
        val host = target.substringBeforeLast(':')
        val port = target.substringAfterLast(':').toInt()
        scope.launch(kotlinx.coroutines.Dispatchers.IO) {
            try {
                Socket().use { sock ->
                    sock.soTimeout = 30_000
                    sock.connect(InetSocketAddress(host, port), 10_000)
                    val toLocal = launch {
                        try {
                            while (true) {
                                val chunk = stream.read()
                                if (chunk.isEmpty()) break
                                sock.getOutputStream().write(chunk)
                                sock.getOutputStream().flush()
                            }
                        } catch (_: Exception) {
                        } finally {
                            runCatching { sock.shutdownOutput() }
                        }
                    }
                    val toTor = launch {
                        try {
                            val buf = ByteArray(8192)
                            while (true) {
                                val n = sock.getInputStream().read(buf)
                                if (n <= 0) break
                                stream.write(buf.copyOf(n))
                            }
                        } catch (_: Exception) {
                        }
                    }
                    toLocal.join()
                    toTor.join()
                }
            } catch (e: Exception) {
                System.err.println("HS stream proxy: ${e.message}")
            } finally {
                runCatching { stream.close() }
            }
        }
    }

    suspend fun publish(inst: OnionServiceInstance): Int {
        val publish = publishDescriptor ?: error("OnionServiceManager.publishDescriptor not wired")
        val ensure = ensureHopKeys ?: error("OnionServiceManager.ensureHopKeys not wired")
        val cons = consensus?.invoke() ?: error("no consensus for HS publish")
        check(inst.introPoints.isNotEmpty()) { "no intro points to publish" }
        val period = HsClient.timePeriodForConsensus(cons)
        val introDesc = inst.introPoints.map { ip ->
            val hop = ensure(ip.relay.fingerprintHex)
            val ed = hop.ed25519Identity ?: ip.relay.ed25519Identity
            IntroPointDescriptor(
                linkSpecifiers = LinkSpecifiers.packForRelay(
                    ip.relay.copy(ed25519Identity = ed ?: ip.relay.ed25519Identity),
                    ed,
                ),
                onionKeyNtor = hop.ntorOnionKey,
                authPublic = ip.authKey.publicKey,
                encKey = ip.encKey,
            )
        }
        val revision = System.currentTimeMillis() / 1000L
        val pow = if (inst.config.powEnabled) HsPow.challenge(inst.config.powEffort) else null
        inst.powSeed = pow?.seed?.copyOf()
        val document = HsDescriptorCodec.build(
            HsDescriptorBuildInput(
                publicIdentity = inst.publicKey,
                privateIdentitySeed = inst.privateKey,
                period = period,
                revisionCounter = revision,
                introPoints = introDesc,
                powChallenge = pow,
                authorizedClients = inst.authorizedClients,
            ),
        )
        inst.lastDescriptor = document
        inst.period = period
        Files.writeString(inst.config.directory.resolve("hs_descriptor"), document)
        val blinded = HsKeyBlind.blindPublicKey(inst.publicKey, period)
        inst.blindedPublic = blinded
        val blindedB64 = java.util.Base64.getEncoder().withoutPadding().encodeToString(blinded)
        emitHsDesc?.invoke(HsControl.descEventCreated(inst.address, blindedB64))
        emitHsDesc?.invoke(HsControl.descEventUpload(inst.address, "HSDir", blindedB64))
        val n = publish(document, blinded)
        HsMetrics.noteDescUpload()
        descriptorCache.storeAsDir(blindedB64, document)
        emitHsDesc?.invoke(HsControl.descEventUploaded(inst.address, "HSDir"))
        println("HS published ${inst.address} to $n HSDirs (rev=$revision)")
        return n
    }

    fun addOnion(ports: List<Pair<Int, String>>, directory: Path? = null): OnionServiceInstance {
        val dir = directory ?: config.dataDirectory.resolve("hs/add_${System.nanoTime().toString(16)}")
        val hs = HiddenServiceConfig(dir, ports.map { HiddenServicePort(it.first, it.second) })
        val inst = startOne(hs)
        running += inst
        return inst
    }

    fun delOnion(serviceId: String): Boolean {
        val want = serviceId.lowercase().removeSuffix(".onion")
        val inst = running.firstOrNull {
            it.address.lowercase().removeSuffix(".onion") == want
        } ?: return false
        inst.introPoints.forEach { it.circuit.close() }
        inst.introPoints.clear()
        running.remove(inst)
        return true
    }

    fun list(): List<OnionServiceInstance> = running.toList()

    fun stopAll() {
        publishJob?.cancel()
        for (inst in running) {
            inst.introPoints.forEach { it.circuit.close() }
            inst.introPoints.clear()
            inst.introTable.clear()
        }
        running.clear()
        HsSys.shutdown()
    }
}
