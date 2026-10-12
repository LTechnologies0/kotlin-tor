package org.kotlintor

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.dir.DirHttp
import org.kotlintor.dir.MicrodescParser
import org.kotlintor.circuit.Circuit
import org.kotlintor.circuit.CircuitManager
import org.kotlintor.circuit.HopKeys
import org.kotlintor.circuit.TorStream
import org.kotlintor.config.IsolationFlag
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.dir.RouterStatus
import org.kotlintor.hs.HsClient
import org.kotlintor.hs.OnionClient
import org.kotlintor.path.CircuitPath
import org.kotlintor.path.PathSelector
import org.kotlintor.util.readTextCompat
import java.nio.file.Files

class TorClient(
    private val config: TorConfig,
    private val scope: CoroutineScope,
    private val emitEvent: (TorEvent) -> Unit = {},
    firstHopDialer: (suspend (host: String, port: Int) -> java.net.Socket)? = null,
) {
    /** True when resolve uses fail-closed DNSSEC stub. */
    val dnssecValidate: Boolean
        get() = config.dnssecMode == org.kotlintor.net.dns.DnssecMode.VALIDATE

    private val bootstrap = BootstrapTracker { line -> emitEvent(TorEvent.Bootstrap(line)) }
    private val dir = DirectoryClient(
        config.dataDirectory.resolve("dir"),
        authorities = buildAuthorities(config),
    )
    private val paths = PathSelector(config, config.dataDirectory.resolve("state/guards"))
    private val circuits = CircuitManager(
        scope,
        { line -> emitEvent(TorEvent.Circ(line)) },
        firstHopDialer,
        circuitBuildTimeoutMs = (config.circuitBuildTimeoutSec * 1000L).coerceAtLeast(5_000L),
        learnCircuitBuildTimeout = config.learnCircuitBuildTimeout,
        pathBiasOptions = config.pathBias.copy(
            dropGuards = config.pathBias.dropGuards || config.pathBiasDropGuards,
        ),
    ).also {
        it.pathBias.dropGuards = config.pathBias.dropGuards || config.pathBiasDropGuards
        it.pathBias.onGuardDropped = { fp -> paths.entryGuardFsm.disableForPathBias(fp) }
        if (config.circuitPriorityHalflifeMsec > 0) {
            it.applyConsensusParams(
                mapOf("CircuitPriorityHalflifeMsec" to config.circuitPriorityHalflifeMsec),
            )
        }
        it.schedulerPreference = config.schedulers
        it.circuitPaddingEnabled = config.circuitPadding && !config.reducedPadding
        it.reducedChannelPadding = config.reducedPadding
        it.connectionPaddingEnabled = when (config.padding) {
            org.kotlintor.config.AutoBool.NO -> false
            org.kotlintor.config.AutoBool.YES -> true
            org.kotlintor.config.AutoBool.AUTO -> when (config.connectionPadding) {
                org.kotlintor.config.AutoBool.NO -> false
                org.kotlintor.config.AutoBool.YES -> true
                org.kotlintor.config.AutoBool.AUTO -> !config.reducedPadding
            }
        }
        it.outboundBindOr = config.outboundBindForOr()
        it.constrainedSockSize = if (config.process.constrainedSockets) {
            config.process.constrainedSockSize
        } else {
            null
        }
        val tcpProxy = config.runtime.tcpProxy
        if (!tcpProxy.isNullOrBlank()) {
            val hostPort = parseHostPort(tcpProxy)
            if (hostPort != null) {
                it.tcpProxyHost = hostPort.first
                it.tcpProxyPort = hostPort.second
                it.tcpProxyProtocol = config.runtime.tcpProxyProtocol
            }
        }
    }

    private fun parseHostPort(spec: String): Pair<String, Int>? {
        val t = spec.trim()
        val idx = t.lastIndexOf(':')
        if (idx <= 0) return null
        val host = t.substring(0, idx).removePrefix("[").removeSuffix("]")
        val port = t.substring(idx + 1).toIntOrNull() ?: return null
        if (host.isEmpty() || port !in 1..65535) return null
        return host to port
    }

    private val automap: org.kotlintor.net.AutomapAddressMap? =
        if (config.automapHostsOnResolve) {
            org.kotlintor.net.AutomapAddressMap(
                virtualNetworkCidr = config.virtualAddrNetworkIpv4,
                suffixes = config.automapHostsSuffixes,
            )
        } else {
            null
        }
    private val geoIpDb: org.kotlintor.dir.GeoIp.Database? =
        config.geoIpFile?.let { path ->
            runCatching {
                org.kotlintor.dir.GeoIp.parseTorFormat(path.readTextCompat())
            }.getOrNull()
        }.also { db ->
            org.kotlintor.stats.GeoIpStats.setGeoDb(db)
        }
    init {
        paths.geoIp = geoIpDb
        val s = config.statsOptions
        org.kotlintor.stats.ConnStats.enabled = s.connDirectionStatistics || s.extraInfoStatistics
        org.kotlintor.stats.GeoIpStats.entryEnabled = s.entryStatistics
        org.kotlintor.stats.GeoIpStats.dirReqEnabled = s.dirReqStatistics
        org.kotlintor.stats.HsStats.enabled = s.hiddenServiceStatistics
    }
    private val mutex = Mutex()
    private var consensus: Consensus? = null
    private val hopKeys = linkedMapOf<String, HopKeys>()
    /** Indexed consensus relays (C Tor routerlist lite). */
    val routerList: org.kotlintor.dir.RouterList = org.kotlintor.dir.RouterList()
    /** Default (no isolation) exit circuit. */
    private var readyCircuit: Circuit? = null
    /** IsolateSOCKSAuth: one exit circuit per SOCKS username. */
    private val isolatedCircuits = linkedMapOf<String, Circuit>()
    private val inFlightBuilds = linkedMapOf<String, CompletableDeferred<Circuit>>()
    private var dirCircuit: Circuit? = null
    private val onionClient = OnionClient(
        dir = dir,
        paths = paths,
        buildCircuit = { path, keys -> circuits.buildCircuit(path, keys) },
        ensureHopKeys = { fp ->
            ensureHopKeys(fp)
            hopKeys[fp]!!
        },
        identityCacheDir = config.dataDirectory.resolve("dir"),
    )

    val bootstrapTracker: BootstrapTracker get() = bootstrap
    /** True only after bootstrap progress reaches [BootstrapPhase.DONE] (100). */
    val isBootstrapped: Boolean get() = bootstrap.phase.value.progress >= BootstrapPhase.DONE.progress
    /** Circuit-ready: DONE bootstrap and an open ready circuit. */
    val isCircuitReady: Boolean get() = isBootstrapped && hasCircuit
    val hasCircuit: Boolean get() = readyCircuit != null

    fun circuitStatusLines(): List<String> = circuits.circuitStatusLines()

    suspend fun bootstrap(buildCircuit: Boolean = true) {
        Files.createDirectories(config.dataDirectory)
        val flavor = if (config.useMicrodescriptors) "microdesc" else "ns"
        bootstrap.advance(
            BootstrapPhase.CONN_DIR,
            summary = "Connecting to directory authority",
        )
        bootstrap.advance(
            BootstrapPhase.HANDSHAKE_DIR,
            summary = "Finishing handshake with directory server",
        )
        bootstrap.advance(
            BootstrapPhase.REQUESTING_STATUS,
            summary = "Fetching $flavor consensus",
        )
        val c0 = if (config.useMicrodescriptors) {
            runCatching { dir.fetchMicrodescConsensus() }.getOrElse { dir.fetchConsensus() }
        } else {
            dir.fetchConsensus()
        }
        var c = c0
        consensus = c
        routerList.clear()
        routerList.addAll(c.relays)
        circuits.applyConsensusParams(c.params)
        paths.noteConsensusParams(c.params)
        runCatching { attachDirectoryGuard(c) }
        if (dir.beginDirGet != null) {
            c = runCatching { enrichFromMicrodescs(c) }.getOrDefault(c)
            consensus = c
            routerList.clear()
            routerList.addAll(c.relays)
        }
        bootstrap.advance(
            BootstrapPhase.LOADING_STATUS,
            summary = "Loaded consensus: ${c.relays.size} relays valid-after=${c.validAfter}",
        )
        bootstrap.advance(
            BootstrapPhase.LOADING_KEYS,
            summary = "Loading authority certificates / verifying consensus",
        )
        bootstrap.advance(
            BootstrapPhase.REQUESTING_DESCRIPTORS,
            summary = if (config.useMicrodescriptors) {
                "Fetching microdescriptors for path selection"
            } else {
                "Fetching server descriptors for path selection"
            },
        )

        val path = paths.select(c.relays)
        ensureHopKeys(path.guard.fingerprintHex)
        ensureHopKeys(path.middle.fingerprintHex)
        ensureHopKeys(path.exit.fingerprintHex)
        bootstrap.advance(
            BootstrapPhase.LOADING_DESCRIPTORS,
            summary = "Loaded hop keys guard=${path.guard.nickname} " +
                "middle=${path.middle.nickname} exit=${path.exit.nickname}",
        )

        if (!buildCircuit) return

        var lastError: Exception? = null
        val excluded = mutableSetOf<String>()
        repeat(8) { attempt ->
            val p = try {
                paths.select(c.relays, extraExclude = excluded, rotateGuard = false)
            } catch (e: Exception) {
                lastError = e
                return@repeat
            }
            try {
                ensureHopKeys(p.guard.fingerprintHex)
                ensureHopKeys(p.middle.fingerprintHex)
                ensureHopKeys(p.exit.fingerprintHex)
                val attemptNote = if (attempt > 0) " (attempt ${attempt + 1})" else ""
                bootstrap.advance(
                    BootstrapPhase.CONN_OR,
                    summary = "Connecting to guard ${p.guard.nickname} " +
                        "${p.guard.ip}:${p.guard.orPort}$attemptNote",
                    forceNotify = attempt > 0,
                )
                bootstrap.advance(
                    BootstrapPhase.HANDSHAKE_OR,
                    summary = "Finishing TLS/ntor handshake with ${p.guard.nickname}",
                )
                bootstrap.advance(
                    BootstrapPhase.CIRCUIT_CREATE,
                    summary = "Establishing circuit " +
                        "${p.guard.nickname}→${p.middle.nickname}→${p.exit.nickname}",
                )
                readyCircuit = circuits.buildCircuit(p, hopKeys)
                dir.circuitExists = true
                paths.confirmGuard(p.guard.fingerprintHex)
                bootstrap.advance(
                    BootstrapPhase.DONE,
                    summary = "Done — circuit via " +
                        "${p.guard.nickname},${p.middle.nickname},${p.exit.nickname}",
                )
                return
            } catch (e: Exception) {
                lastError = e
                System.err.println(
                    "circuit attempt ${attempt + 1} failed: ${e.javaClass.simpleName}: ${e.message}",
                )
                paths.noteGuardFailure(p.guard.fingerprintHex)
                excluded += p.guard.fingerprintHex
            }
        }
        throw IllegalStateException("circuit bootstrap failed after retries", lastError)
    }

    /**
     * Open a stream to [host]:[port].
     * [isolationKey] is typically the SOCKS5 username when IsolateSOCKSAuth is set;
     * prefer [connect] with client/dest metadata via [buildIsolationKey].
     */
    suspend fun connect(
        host: String,
        port: Int,
        isolationKey: String? = null,
        clientAddr: String? = null,
        optimisticData: Boolean = config.optimisticData,
    ): TorStream {
        if (dormant) error("TorClient dormant: refusing new streams")
        val mapped = if (config.mapAddress.isEmpty()) {
            host
        } else {
            org.kotlintor.net.MapAddress.apply(
                host,
                config.mapAddress.map { org.kotlintor.net.MapAddress.Rule(it.first, it.second) },
            )
        }
        // Automap: reverse virtual IP → original hostname (.onion).
        val dest = automap?.reverse(mapped) ?: mapped
        if (config.safeSocks &&
            !HsClient.isOnionHost(dest) &&
            !org.kotlintor.net.SafeSocksPolicy.allows(
                dest,
                safeSocks = true,
                allowIpLiterals = config.safeSocksAllowIpLiterals,
            )
        ) {
            if (config.warnUnsafeSocks || config.testSocks) {
                System.err.println("SafeSocks: rejecting IP-literal destination $dest")
            }
            error("SafeSocks: refusing IP literal $dest (use a hostname)")
        }
        if (config.clientRejectInternalAddresses &&
            !HsClient.isOnionHost(dest) &&
            org.kotlintor.net.PrivateAddresses.isPrivateLiteral(dest)
        ) {
            error("ClientRejectInternalAddresses: refusing private destination $dest")
        }
        if (HsClient.isOnionHost(dest)) {
            val c = mutex.withLock { consensus } ?: error("no consensus; call bootstrap() first")
            return onionClient.connect(dest, port, c)
        }
        val key = buildIsolationKey(
            socksUser = isolationKey,
            host = dest,
            port = port,
            clientAddr = clientAddr,
        )
        val circ = obtainCircuit(key, dest, exitPort = port)
        return circ.openStream(dest, port, optimisticData = optimisticData)
    }

    /**
     * Open a stream on a circuit keyed by [circuitIsolationKey] verbatim
     * (does not go through [buildIsolationKey]). Used for DNSSEC TCP so one
     * DNS resolve owns exactly one circuit regardless of SOCKS isolation flags.
     */
    private suspend fun connectOnCircuitKey(
        host: String,
        port: Int,
        circuitIsolationKey: String,
        optimisticData: Boolean = config.optimisticData,
    ): TorStream {
        if (dormant) error("TorClient dormant: refusing new streams")
        val dest = automap?.reverse(host) ?: host
        val circ = obtainCircuit(circuitIsolationKey, dest, exitPort = port)
        return circ.openStream(dest, port, optimisticData = optimisticData)
    }

    /**
     * Resolve [hostname] via RELAY RESOLVE, or DNSSEC stub when [TorConfig.dnssecMode]
     * is Validate (fail-closed local validation over Tor TCP DNS).
     *
     * **Circuit isolation:** each call uses a fresh dedicated circuit (never the
     * shared SOCKS/[readyCircuit] pool). DNSSEC TCP queries for the same call share
     * that one circuit; it is closed when the resolve completes.
     */
    suspend fun resolve(hostname: String): List<String> {
        val dnsIso = newDnsRequestIsolationKey(hostname)
        mutex.withLock {
            if (automap != null && automap.shouldAutomap(hostname)) {
                return listOf(automap.getOrAssign(hostname))
            }
        }
        if (config.clientDnsRejectInternalAddresses &&
            org.kotlintor.net.PrivateAddresses.isPrivateLiteral(hostname)
        ) {
            return emptyList()
        }
        if (config.dnssecMode == org.kotlintor.net.dns.DnssecMode.VALIDATE) {
            return try {
                resolveDnssec(hostname, dnsIso)
            } finally {
                mutex.withLock { releaseDnsRequestCircuit(dnsIso) }
            }
        }
        val circ = obtainCircuit(dnsIso, hostname)
        return try {
            circ.resolve(hostname)
        } finally {
            mutex.withLock { releaseDnsRequestCircuit(dnsIso) }
        }
    }

    private suspend fun resolveDnssec(hostname: String, dnsIso: String): List<String> {
        val (host, port) = org.kotlintor.net.dns.parseRecursiveEndpoint(config.dnssecRecursive)
        val anchors = org.kotlintor.net.dns.TrustAnchors.load(config.dnssecTrustAnchorFile)
        val stub = org.kotlintor.net.dns.DnssecStubResolver(
            recursiveHost = host,
            recursivePort = port,
            trustAnchors = anchors,
            openPipe = { h, p ->
                // Same isolation key ⇒ one circuit for all TCP DNS of this resolve.
                org.kotlintor.net.TorStreamBytePipe(
                    connectOnCircuitKey(h, p, circuitIsolationKey = dnsIso),
                )
            },
        )
        return stub.resolve(hostname)
    }

    /** Unique key so each DNS resolve builds (and later tears down) its own circuit. */
    internal fun newDnsRequestIsolationKey(hostname: String): String =
        "dns:${hostname.lowercase()}|${java.util.UUID.randomUUID()}"

    private fun releaseDnsRequestCircuit(dnsIso: String) {
        isolatedCircuits.remove(dnsIso)?.close()
        inFlightBuilds.remove(dnsIso)
    }

    private suspend fun attachDirectoryGuard(c: Consensus) {
        val dirRelays = c.relays.filter {
            it.isRunning && "V2Dir" in it.flags && it.orPort > 0
        }.ifEmpty {
            authoritiesAsRouters()
        }
        if (dirRelays.isEmpty()) return
        val pick = dirRelays[kotlin.random.Random.nextInt(dirRelays.size)]
        val circ = try {
            circuits.buildOneHopDirCircuit(pick, useCreateOnehop = true)
        } catch (_: Exception) {
            circuits.buildOneHopDirCircuit(pick, useCreateOnehop = false)
        }
        dirCircuit = circ
        dir.circuitExists = true
        dir.beginDirGet = { path ->
            val stream = circ.openDirStream()
            try {
                DirHttp.httpGetOverPipe(
                    write = { b -> stream.write(b) },
                    readAll = { stream.readHttpResponse() },
                    path = path,
                )
            } finally {
                runCatching { stream.close() }
            }
        }
    }

    private fun authoritiesAsRouters(): List<RouterStatus> =
        org.kotlintor.dir.DefaultAuthorities.ALL.map { a ->
            val id = org.kotlintor.util.hexToBytes(a.v3Ident)
            RouterStatus(
                nickname = a.nickname,
                identity = id,
                digest = ByteArray(20),
                publication = java.time.Instant.EPOCH,
                ip = a.address,
                orPort = a.orPort,
                dirPort = a.dirPort,
                flags = setOf("Running", "Fast", "V2Dir", "Authority"),
                version = null,
                proto = emptyMap(),
                bandwidth = 1,
            )
        }

    private suspend fun enrichFromMicrodescs(c: Consensus): Consensus {
        val withDigest = c.relays.filter { it.microdescDigest != null }
        val missing = withDigest.mapNotNull { it.microdescDigest }
        val byHex = LinkedHashMap<String, String>()
        for (chunk in missing.chunked(16)) {
            val got = dir.fetchMicrodescriptors(chunk)
            byHex.putAll(got)
        }
        val updated = c.relays.map { r ->
            val d = r.microdescDigest ?: return@map r
            val body = byHex[d.joinToString("") { "%02x".format(it) }] ?: return@map r
            val ntor = MicrodescParser.parseOnionKey(body)
            if (ntor != null && r.fingerprintHex !in hopKeys) {
                hopKeys[r.fingerprintHex] = HopKeys(ntor, DescriptorParser.parseEd25519Identity(body))
            }
            r.copy(
                ntorOnionKey = ntor ?: r.ntorOnionKey,
                ed25519Identity = DescriptorParser.parseEd25519Identity(body) ?: r.ed25519Identity,
                exitPolicySummary = MicrodescParser.parseExitPolicySummary(body) ?: r.exitPolicySummary,
            )
        }
        return c.copy(relays = updated)
    }

    private fun dirtyTimeoutMsFor(isolationKey: String?): Long {
        if (isolationKey != null &&
            IsolationFlag.KeepAliveIsolateSOCKSAuth in config.isolationFlags &&
            IsolationFlag.IsolateSOCKSAuth in config.isolationFlags
        ) {
            return Long.MAX_VALUE / 4 // prop368 IsoCDT ≈ infinity
        }
        return config.circuitDirtyTimeoutSec * 1000L
    }

    fun buildIsolationKey(
        socksUser: String?,
        host: String,
        port: Int,
        clientAddr: String?,
        protocol: String = "socks",
    ): String? {
        val parts = mutableListOf<String>()
        val flags = config.isolationFlags
        if (IsolationFlag.IsolateSOCKSAuth in flags && !socksUser.isNullOrEmpty()) {
            parts += "auth=$socksUser"
        }
        if (IsolationFlag.IsolateDestAddr in flags) parts += "dst=$host"
        if (IsolationFlag.IsolateDestPort in flags) parts += "dport=$port"
        if (IsolationFlag.IsolateClientAddr in flags && !clientAddr.isNullOrEmpty()) {
            parts += "caddr=$clientAddr"
        }
        if (IsolationFlag.IsolateClientProtocol in flags) parts += "proto=$protocol"
        return parts.takeIf { it.isNotEmpty() }?.joinToString("|")
    }

    private suspend fun obtainCircuit(
        isolationKey: String?,
        host: String,
        exitPort: Int? = null,
    ): Circuit {
        val mapKey = isolationKey ?: DEFAULT_ISOLATION
        mutex.withLock {
            peekLiveCircuit(isolationKey)?.let { return it }
        }
        val created = CompletableDeferred<Circuit>()
        val waiter: CompletableDeferred<Circuit>? = mutex.withLock {
            peekLiveCircuit(isolationKey)?.let { existing ->
                created.complete(existing)
                return@withLock null
            }
            val inflight = inFlightBuilds[mapKey]
            if (inflight != null) {
                inflight
            } else {
                inFlightBuilds[mapKey] = created
                null
            }
        }
        if (waiter != null) return waiter.await()
        try {
            val circ = buildFreshCircuit(isolationKey, host, exitPort)
            mutex.withLock {
                if (isolationKey.isNullOrEmpty()) {
                    readyCircuit = circ
                } else {
                    evictIsolatedIfNeeded()
                    isolatedCircuits[isolationKey] = circ
                }
                inFlightBuilds.remove(mapKey)
            }
            created.complete(circ)
            return circ
        } catch (e: Exception) {
            mutex.withLock { inFlightBuilds.remove(mapKey) }
            created.completeExceptionally(e)
            throw e
        }
    }

    private fun peekLiveCircuit(isolationKey: String?): Circuit? {
        if (!isolationKey.isNullOrEmpty()) {
            val existing = isolatedCircuits[isolationKey] ?: return null
            if (!existing.dead && !existing.isTooDirtyForAttach(dirtyTimeoutMsFor(isolationKey))) {
                return existing
            }
            existing.close()
            isolatedCircuits.remove(isolationKey)
            return null
        }
        val existing = readyCircuit ?: return null
        if (!existing.dead && !existing.isTooDirtyForAttach(dirtyTimeoutMsFor(null))) {
            return existing
        }
        existing.close()
        readyCircuit = null
        return null
    }

    private suspend fun buildFreshCircuit(
        isolationKey: String?,
        host: String,
        exitPort: Int?,
    ): Circuit {
        val c = mutex.withLock { consensus } ?: error("no consensus; call bootstrap() first")
        val path = paths.select(c.relays, host, exitPort = exitPort)
        ensureHopKeys(path.guard.fingerprintHex)
        ensureHopKeys(path.middle.fingerprintHex)
        ensureHopKeys(path.exit.fingerprintHex)
        val circ = circuits.buildCircuit(path, hopKeys)
        paths.confirmGuard(path.guard.fingerprintHex)
        dir.circuitExists = true
        bootstrap.advance(BootstrapPhase.DONE)
        return circ
    }

    /** Download encrypted onion service v3 descriptor via BEGIN_DIR to responsible HSDirs. */
    suspend fun fetchOnionDescriptor(onionAddress: String): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.fetchDescriptor(onionAddress, c)
    }

    /** Fetch and decrypt a v3 onion descriptor (intro points plaintext). */
    suspend fun fetchAndDecryptOnionDescriptor(onionAddress: String): OnionClient.FetchedDescriptor {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.fetchAndDecrypt(onionAddress, c)
    }

    /** Debug: fetch HS descriptor from a named consensus relay via BEGIN_DIR. */
    suspend fun fetchOnionDescriptorVia(
        onionAddress: String,
        relayNicknameOrFp: String,
    ): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        val key = relayNicknameOrFp.uppercase()
        val relay = c.relays.find {
            it.nickname.equals(relayNicknameOrFp, true) || it.fingerprintHex == key
        } ?: error("relay not in consensus: $relayNicknameOrFp")
        return onionClient.fetchDescriptorFromRelay(onionAddress, c, relay)
    }

    /** Debug: BEGIN_DIR fetch against an explicit relay (may be absent from local consensus). */
    suspend fun fetchOnionDescriptorViaRelay(
        onionAddress: String,
        nickname: String,
        ip: String,
        orPort: Int,
        fingerprintHex: String,
    ): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        val fp = fingerprintHex.uppercase()
        val identity = org.kotlintor.util.hexToBytes(fp)
        val relay = RouterStatus(
            nickname = nickname,
            identity = identity,
            digest = ByteArray(20),
            publication = c.validAfter,
            ip = ip,
            orPort = orPort,
            dirPort = 0,
            flags = setOf("Running", "Fast", "HSDir", "V2Dir"),
            version = null,
            proto = emptyMap(),
            bandwidth = 1,
        )
        // Ensure path selection can still find guards/middles from consensus.
        return onionClient.fetchDescriptorFromRelay(onionAddress, c, relay)
    }

    private suspend fun ensureHopKeys(fp: String) {
        if (fp in hopKeys) return
        val c = mutex.withLock { consensus }
        val rs = c?.relays?.find { it.fingerprintHex.equals(fp, true) }
        if (rs?.ntorOnionKey != null) {
            hopKeys[fp] = HopKeys(rs.ntorOnionKey, rs.ed25519Identity)
            trimHopKeys()
            return
        }
        if (rs?.microdescDigest != null) {
            val got = dir.fetchMicrodescriptors(listOf(rs.microdescDigest))
            val hex = rs.microdescDigest.joinToString("") { "%02x".format(it) }
            val body = got[hex] ?: error("no microdesc for $fp (digest $hex)")
            val ntor = MicrodescParser.parseOnionKey(body) ?: error("no ntor-onion-key in microdesc $fp")
            hopKeys[fp] = HopKeys(ntor, DescriptorParser.parseEd25519Identity(body) ?: rs.ed25519Identity)
            trimHopKeys()
            return
        }
        if (dir.beginDirGet == null && dir.circuitExists) {
            error("BEGIN_DIR required for hop keys of $fp; refusing cleartext /tor/server/fp")
        }
        val expected = if (rs != null && rs.digest.any { it != 0.toByte() }) {
            mapOf(fp.uppercase() to rs.digest)
        } else {
            emptyMap()
        }
        val docs = dir.fetchServerDescriptors(listOf(fp), expected)
        val doc = docs[fp.uppercase()] ?: error("no descriptor for $fp")
        val parsed = DescriptorParser.parse(doc, fp) ?: error("bad descriptor for $fp")
        hopKeys[fp] = HopKeys(parsed.ntorOnionKey, parsed.ed25519Identity)
        trimHopKeys()
        val family = DescriptorParser.parseFamily(doc)
        if (family.isNotEmpty()) {
            paths.noteFamily(fp, family)
        }
    }

    private fun trimHopKeys() {
        while (hopKeys.size > MAX_HOP_KEYS) {
            val oldest = hopKeys.keys.firstOrNull() ?: break
            hopKeys.remove(oldest)
        }
    }

    private fun evictIsolatedIfNeeded() {
        while (isolatedCircuits.size >= MAX_ISOLATED_CIRCUITS) {
            val oldest = isolatedCircuits.entries.firstOrNull() ?: break
            oldest.value.close()
            isolatedCircuits.remove(oldest.key)
        }
    }

    fun newnym() {
        readyCircuit?.close()
        readyCircuit = null
        isolatedCircuits.values.forEach { it.close() }
        isolatedCircuits.clear()
        inFlightBuilds.clear()
        paths.clearRecentHops()
    }

    /** Drop ready + isolated circuits (OnionTunnel RefreshCircuits). */
    fun refreshCircuits() = newnym()

    /**
     * Soft dormant flag for OnionTunnel scaffolding.
     * When dormant, [connect] refuses new streams until cleared.
     */
    @Volatile
    var dormant: Boolean = false
        private set

    fun setDormant(value: Boolean) {
        dormant = value
    }

    fun consensusOrNull(): Consensus? = consensus

    /** HS host: build an arbitrary circuit path. */
    suspend fun buildCircuitForHs(path: CircuitPath, keys: Map<String, HopKeys>): Circuit =
        circuits.buildCircuit(path, keys)

    suspend fun hopKeysFor(fp: String): HopKeys {
        ensureHopKeys(fp)
        return hopKeys[fp]!!
    }

    fun selectPathEndingAt(relays: List<RouterStatus>, last: RouterStatus): CircuitPath =
        paths.selectEndingAt(relays, last)

    fun sampledGuardStatusLines(): List<String> =
        paths.sampledEntries().map { e ->
            val status = when {
                e.confirmed -> "confirmed"
                else -> "unconfirmed"
            }
            "${e.fingerprintHex} $status first=${e.firstListedMs}"
        }

    /** Upload a signed HS v3 descriptor to responsible HSDirs. */
    suspend fun publishOnionDescriptor(document: String, blindedPublic: ByteArray): Int {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.publishDescriptor(document, blindedPublic, c)
    }

    companion object {
        const val MAX_HOP_KEYS = 512
        const val MAX_ISOLATED_CIRCUITS = 128
        private const val DEFAULT_ISOLATION = ""

        fun buildAuthorities(config: TorConfig): List<org.kotlintor.dir.DirectoryAuthority> {
            if (config.dirAuthorities.isNotEmpty()) return config.dirAuthorities
            val fallbacks = if (config.useDefaultFallbackDirs) {
                config.fallbackDirs
            } else {
                config.fallbackDirs
            }
            return if (fallbacks.isNotEmpty()) {
                fallbacks
            } else {
                org.kotlintor.dir.DefaultAuthorities.ALL
            }
        }
    }
}
