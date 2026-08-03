package org.kotlintor

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.config.PidFile
import org.kotlintor.config.TorConfig
import org.kotlintor.hs.OnionServiceManager
import org.kotlintor.pt.PtManager
import org.kotlintor.relay.RelayService
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

sealed class TorEvent {
    data class Bootstrap(val line: String) : TorEvent()
    data class Circ(val line: String) : TorEvent()
    data class Stream(val line: String) : TorEvent()
    data class Notice(val message: String) : TorEvent()
    data class Warn(val message: String) : TorEvent()
    data class Bandwidth(val read: Long, val written: Long) : TorEvent()
    data class OrConn(val line: String) : TorEvent()
    data class HsDesc(val line: String) : TorEvent()
    data class AddrMap(val line: String) : TorEvent()
    data class NewDesc(val line: String) : TorEvent()
    data class Guard(val line: String) : TorEvent()
    data class ConfChanged(val line: String) : TorEvent()
    data class CircMinor(val line: String) : TorEvent()
    data class ClientsSeen(val line: String) : TorEvent()
}

/**
 * Process-shaped daemon owning client, optional relay, HS, and PT manager.
 * SOCKS/control listeners are attached by `:proxy` / `:control` modules.
 */
class TorDaemon(
    val config: TorConfig,
    parent: CoroutineScope? = null,
) {
    private val job = SupervisorJob(parent?.coroutineContext?.get(kotlinx.coroutines.Job))
    val scope = CoroutineScope(job + kotlinx.coroutines.Dispatchers.Default)
    private val started = AtomicBoolean(false)
    private val _events = MutableSharedFlow<TorEvent>(extraBufferCapacity = 256)
    val events: SharedFlow<TorEvent> = _events.asSharedFlow()

    val pluggableTransports = PtManager(config)
    private val serverPluggableTransports = org.kotlintor.pt.PtServerManager(config)
    val client: TorClient = TorClient(
        config,
        scope,
        emitEvent = { emit(it) },
        firstHopDialer = if (config.useBridges) {
            { host, port ->
                val bridge = pluggableTransports.firstBridge()
                    ?: error("UseBridges set but no Bridge lines")
                val target = if (bridge.host == host && bridge.port == port) {
                    bridge
                } else {
                    bridge
                }
                pluggableTransports.dialBridge(target)
            }
        } else {
            null
        },
    )
    val onionServices = OnionServiceManager(config, scope)
    val relay = RelayService(config, scope)
    private var extOr: org.kotlintor.pt.ExtOrPortServer? = null
    private var dirAuthLoop: org.kotlintor.dir.DirAuthPublishLoop? = null
    private val bytesRead = AtomicLong(0)
    private val bytesWritten = AtomicLong(0)

    /** Mutable runtime overrides from SETCONF (subset). */
    val runtimeOverrides: MutableMap<String, String> = linkedMapOf()

    val controlCookiePath: Path get() = config.dataDirectory.resolve("control_auth_cookie")

    fun noteBandwidth(read: Long = 0, written: Long = 0) {
        if (read > 0) bytesRead.addAndGet(read)
        if (written > 0) bytesWritten.addAndGet(written)
    }

    fun confValue(key: String): String? {
        runtimeOverrides[key.uppercase()]?.let { return it }
        return when (key.uppercase()) {
            "DATADIRECTORY" -> config.dataDirectory.toString()
            "SOCKSPORT" -> config.socksPorts.firstOrNull()?.toString()
            "CONTROLPORT" -> config.controlPorts.firstOrNull()?.toString()
            "COOKIEAUTHENTICATION" -> if (config.cookieAuthentication) "1" else "0"
            "USEBRIDGES" -> if (config.useBridges) "1" else "0"
            "EXITRELAY" -> if (config.exitRelay) "1" else "0"
            "REDUCEDEXITPOLICY" -> if (config.reducedExitPolicy) "1" else "0"
            "CIRCUITDIRTYTIMEOUT" -> config.circuitDirtyTimeoutSec.toString()
            "CLIENTONLY" -> if (config.clientOnly) "1" else "0"
            "VANGUARDSLITEENABLED" -> if (config.vanguardsLiteEnabled) "1" else "0"
            "HEARTBEATPERIOD" -> config.heartbeatPeriodSec.toString()
            "DISABLENETWORK" -> if (config.disableNetwork) "1" else "0"
            "NICKNAME" -> config.nickname
            "CONTACTINFO" -> config.contactInfo
            "BANDWIDTHRATE" -> config.bandwidthRateBytes.toString()
            "BANDWIDTHBURST" -> config.bandwidthBurstBytes.toString()
            "SANDBOX" -> if (config.sandbox) "1" else "0"
            "CIRCUITBUILDTIMEOUT" -> config.circuitBuildTimeoutSec.toString()
            "MAXCLIENTCIRCUITSPENDING" -> config.maxClientCircuitsPending.toString()
            "CONNLIMIT" -> config.connLimit.toString()
            "KEEPALIVEPERIOD" -> config.keepalivePeriodSec.toString()
            "FETCHDIRINFOEARLY" -> if (config.fetchDirInfoEarly) "1" else "0"
            "FETCHDIRINFOEXTRAEARLY" -> if (config.fetchDirInfoExtraEarly) "1" else "0"
            "BRIDGERELAY" -> if (config.bridgeRelay) "1" else "0"
            "EXTENDALLOWPRIVATEADDRESSES" -> if (config.extendAllowPrivateAddresses) "1" else "0"
            "DIRALLOWPRIVATEADDRESSES" -> if (config.dirAllowPrivateAddresses) "1" else "0"
            "REFUSEUNKNOWNEXITS" -> config.refuseUnknownExits.toTorrc()
            "ASSUMEREACHABLE" -> if (config.assumeReachable) "1" else "0"
            "AVOIDDISKWRITES" -> if (config.avoidDiskWrites) "1" else "0"
            "DISABLEDEBUGGERATTACHMENT" -> if (config.disableDebuggerAttachment) "1" else "0"
            "CLIENTTRANSPORTPLUGIN" -> config.clientTransportPlugin
            "SERVERTRANSPORTPLUGIN" -> config.serverTransportPlugin
            else -> config.acknowledgedKeys.entries
                .firstOrNull { it.key.equals(key, ignoreCase = true) }
                ?.value
                ?: config.unrecognizedKeys.entries
                    .firstOrNull { it.key.equals(key, ignoreCase = true) }
                    ?.value
        }
    }

    suspend fun start(buildCircuit: Boolean = true) {
        check(started.compareAndSet(false, true)) { "already started" }
        Files.createDirectories(config.dataDirectory)
        PidFile.write(config.process.pidFile)
        if (config.sandbox) {
            val r = org.kotlintor.os.LinuxSandbox.apply(
                dataDirectory = config.dataDirectory,
                maxOpenFiles = config.connLimit.toLong().coerceAtLeast(256),
                enableSeccomp = true,
                denyPtrace = config.disableDebuggerAttachment,
            )
            emit(
                TorEvent.Notice(
                    "Sandbox: dir=${r.dataDirHardened} nnp=${r.noNewPrivs} rlim=${r.rlimits} " +
                        "seccomp=${r.seccomp} ${r.notes.joinToString()}",
                ),
            )
        }
        if (config.cookieAuthentication) {
            val cookie = org.kotlintor.util.SecureRandomSource.nextBytes(32)
            Files.write(controlCookiePath, cookie)
        }
        if (config.disableNetwork) {
            emit(TorEvent.Notice("DisableNetwork=1: skipping directory bootstrap and OR dials"))
            startOwningControllerWatch()
            emit(TorEvent.Notice("kotlin-tor daemon ready (network disabled)"))
            return
        }
        emit(TorEvent.Bootstrap(client.bootstrapTracker.statusLine))
        if (config.useBridges) {
            pluggableTransports.start()
            val warnings = pluggableTransports.validateConfiguredBridges()
            warnings.forEach { emit(TorEvent.Warn("PT bridge: $it")) }
        }
        try {
            client.bootstrap(buildCircuit = buildCircuit)
        } catch (e: Exception) {
            if (!client.isBootstrapped) throw e
            emit(TorEvent.Warn("circuit bootstrap failed: ${e.message}"))
        }
        emit(TorEvent.Bootstrap(client.bootstrapTracker.statusLine))
        wireOnionServiceManager()
        if (config.hiddenServices.isNotEmpty()) {
            onionServices.startAll()
        }
        if (config.isRelay) {
            relay.start()
            if (config.serverTransportPlugin != null) {
                serverPluggableTransports.start()
                val err = serverPluggableTransports.lastError
                if (err != null) emit(TorEvent.Warn("server PT: $err"))
                else emit(
                    TorEvent.Notice(
                        "server PT SMETHODS=${serverPluggableTransports.smethods}",
                    ),
                )
            }
        }
        if (config.authoritativeDirectory || config.v3AuthoritativeDirectory) {
            startDirAuthLoop()
        }
        if (config.extOrPort != null) {
            val e = org.kotlintor.pt.ExtOrPortServer(config, scope) { sock, user, transport ->
                emit(TorEvent.Notice("ExtORPort client user=$user transport=$transport"))
                runCatching { sock.close() }
            }
            e.start()
            extOr = e
        }
        startOwningControllerWatch()
        startHeartbeat()
        emit(TorEvent.Notice("kotlin-tor daemon ready"))
    }

    /** Exit when OwningControllerProcess dies (control-spec). */
    private fun startOwningControllerWatch() {
        val pid = config.owningControllerProcess ?: return
        scope.launch {
            while (isActive) {
                delay(2_000)
                if (!processAlive(pid)) {
                    emit(TorEvent.Notice("OwningControllerProcess $pid gone; shutting down"))
                    stop()
                    return@launch
                }
            }
        }
    }

    private fun startHeartbeat() {
        val period = (config.heartbeatPeriodSec * 1000L).coerceAtLeast(60_000L)
        scope.launch {
            while (isActive) {
                delay(period)
                emit(
                    TorEvent.Notice(
                        org.kotlintor.status.HeartbeatStatus.format(
                            bytesRead = bytesRead.get(),
                            bytesWritten = bytesWritten.get(),
                            bootstrapped = client.isBootstrapped,
                            circuitsOpen = client.circuitStatusLines().size,
                        ),
                    ),
                )
                emit(TorEvent.Bandwidth(bytesRead.get(), bytesWritten.get()))
            }
        }
    }

    private fun processAlive(pid: Long): Boolean {
        if (pid <= 0) return false
        return try {
            val f = Path.of("/proc/$pid")
            Files.exists(f)
        } catch (_: Exception) {
            false
        }
    }

    private fun wireOnionServiceManager() {
        onionServices.buildCircuit = { path, keys -> client.buildCircuitForHs(path, keys) }
        onionServices.ensureHopKeys = { fp -> client.hopKeysFor(fp) }
        onionServices.selectEndingAt = { relays, last -> client.selectPathEndingAt(relays, last) }
        onionServices.consensus = { client.consensusOrNull() }
        onionServices.publishDescriptor = { doc, blinded -> client.publishOnionDescriptor(doc, blinded) }
        onionServices.emitHsDesc = { line -> emit(TorEvent.HsDesc(line)) }
    }

    /** Start dirvote act loop and attach DirPort vote inbox (AuthoritativeDirectory). */
    private fun startDirAuthLoop() {
        val keysDir = config.dataDirectory.resolve("keys")
        Files.createDirectories(keysDir)
        val material = org.kotlintor.dir.AuthorityCert.loadMaterial(keysDir)
            ?: org.kotlintor.dir.AuthorityCert.generate(bits = 2048).also {
                val doc = it.formatCertificate(
                    address = config.dirPort?.host ?: "127.0.0.1",
                    dirPort = config.dirPort?.port ?: 9030,
                )
                org.kotlintor.dir.AuthorityCert.persist(it, keysDir, doc)
            }
        val fp = material.identityFingerprint.joinToString("") { b -> "%02X".format(b) }
        val timing = if (config.testingTorNetwork) {
            org.kotlintor.dir.DirVote.Timing(
                voteIntervalSec = org.kotlintor.dir.DirVote.MIN_VOTE_INTERVAL_TESTING,
                voteSeconds = 2,
                distSeconds = 2,
                testing = true,
            )
        } else {
            org.kotlintor.dir.DirVote.Timing(
                voteIntervalSec = 300,
                voteSeconds = 20,
                distSeconds = 20,
                testing = false,
            )
        }
        val loop = org.kotlintor.dir.DirAuthPublishLoop(
            scope = scope,
            dataDir = config.dataDirectory.resolve("dirauth"),
            timing = timing,
            knownAuthorities = setOf(fp),
            localAuthority = material,
            onPublish = { attached, _ ->
                emit(TorEvent.Notice("dirauth published consensus (${attached.length} bytes)"))
            },
        )
        loop.attachVoteInbox(relay.voteInbox)
        loop.attachSigInbox(relay.sigInbox)
        loop.start()
        dirAuthLoop = loop
        emit(TorEvent.Notice("DirAuthPublishLoop started fp=$fp (vote+sig inbox ← DirPort)"))
    }

    suspend fun signalNewnym() {
        client.newnym()
        emit(TorEvent.Notice("NEWNYM"))
    }

    fun signalDormant() {
        client.setDormant(true)
        emit(TorEvent.Notice("DORMANT"))
    }

    fun signalActive() {
        client.setDormant(false)
        emit(TorEvent.Notice("ACTIVE"))
    }

    fun isDormant(): Boolean = client.dormant

    fun emit(event: TorEvent) {
        _events.tryEmit(event)
    }

    fun stop() {
        if (!started.get()) return
        dirAuthLoop?.stop()
        dirAuthLoop = null
        relay.stop()
        onionServices.stopAll()
        pluggableTransports.stop()
        serverPluggableTransports.stop()
        extOr?.stop()
        scope.cancel()
        PidFile.delete(config.process.pidFile)
        started.set(false)
    }
}
