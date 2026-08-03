package org.kotlintor.control

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import org.kotlintor.TorDaemon
import org.kotlintor.TorEvent
import org.kotlintor.config.ListenSpec
import org.kotlintor.crypto.ControlS2k
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ControlConnectionHandle
import org.kotlintor.link.ListenerConnection
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.constantTimeEquals
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files

/**
 * Subset of control-spec: PROTOCOLINFO, AUTHCHALLENGE/SAFECOOKIE, AUTHENTICATE,
 * GETINFO, SETEVENTS, SIGNAL, ADD_ONION.
 */
class ControlServer(
    private val daemon: TorDaemon,
    private val scope: CoroutineScope,
    private val maxConcurrent: Int = DEFAULT_MAX_CONCURRENT,
) {
    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null
    private val gate = Semaphore(maxConcurrent.coerceAtLeast(1))

    fun start(listen: ListenSpec = daemon.config.controlPorts.first()) {
        if (!listen.isLoopbackHost()) {
            val cookie = daemon.config.cookieAuthentication
            val hashed = !daemon.config.hashedControlPassword.isNullOrBlank()
            require(cookie || hashed) {
                "ControlPort on non-loopback ${listen.host} requires CookieAuthentication or HashedControlPassword"
            }
        }
        val ss = ServerSocket()
        ss.bind(InetSocketAddress(listen.host, listen.port.let { if (it == 0) 0 else it }))
        server = ss
        val lh = ConnectionTable.newListener(listen.host, ss.localPort, ConnectionType.CONTROL)
        lh.markOpen()
        listenerHandle = lh
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                if (!gate.tryAcquire()) {
                    runCatching { sock.close() }
                    continue
                }
                launch {
                    try {
                        ControlSession(daemon, sock).run()
                    } finally {
                        gate.release()
                    }
                }
            }
        }
    }

    fun boundPort(): Int = server?.localPort ?: -1

    fun stop() {
        runCatching { server?.close() }
        job?.cancel()
        listenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        listenerHandle = null
    }

    companion object {
        const val DEFAULT_MAX_CONCURRENT = 32
    }
}

private class ControlSession(
    private val daemon: TorDaemon,
    private val socket: Socket,
) {
    private var authenticated = false
    private val events = mutableSetOf<String>()
    /** Expected ClientHash after AUTHCHALLENGE SAFECOOKIE (null = not challenged). */
    private var safecookieClientHash: ByteArray? = null
    private var authchallengeUsed = false
    /** After AUTHCHALLENGE, the next command must be AUTHENTICATE. */
    private var expectAuthenticateNext = false
    private val connHandle: ControlConnectionHandle =
        ConnectionTable.newControl(
            socket.inetAddress?.hostAddress ?: "0.0.0.0",
            socket.port,
        ).also { it.markOpen() }

    suspend fun run() = withContext(Dispatchers.IO) {
        val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
        val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))
        val eventJob = launch {
            daemon.events.collect { ev ->
                if (!authenticated) return@collect
                when (ev) {
                    is TorEvent.Bootstrap -> if ("STATUS_CLIENT" in events || "STATUS" in events) {
                        writeAsync(writer, "650 ${ev.line}\r\n")
                    }
                    is TorEvent.Circ -> if ("CIRC" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.Stream -> if ("STREAM" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.Notice -> if ("NOTICE" in events) writeAsync(writer, "650 NOTICE ${ev.message}\r\n")
                    is TorEvent.Warn -> if ("WARN" in events) writeAsync(writer, "650 WARN ${ev.message}\r\n")
                    is TorEvent.Bandwidth -> if ("BW" in events) {
                        writeAsync(writer, "650 BW ${ev.read} ${ev.written}\r\n")
                    }
                    is TorEvent.OrConn -> if ("ORCONN" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.HsDesc -> if ("HS_DESC" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.AddrMap -> if ("ADDRMAP" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.NewDesc -> if ("NEWDESC" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.Guard -> if ("GUARD" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.ConfChanged -> if ("CONF_CHANGED" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.CircMinor -> if ("CIRC_MINOR" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                    is TorEvent.ClientsSeen -> if ("CLIENTS_SEEN" in events) writeAsync(writer, "650 ${ev.line}\r\n")
                }
            }
        }
        try {
            while (true) {
                val line = reader.readLine() ?: break
                handle(line.trim(), writer, reader)
            }
        } finally {
            eventJob.cancel()
            connHandle.markClosed()
            ConnectionTable.remove(connHandle.id)
            runCatching { socket.close() }
        }
    }

    private suspend fun writeAsync(writer: BufferedWriter, s: String) = withContext(Dispatchers.IO) {
        synchronized(writer) {
            writer.write(s)
            writer.flush()
        }
    }

    private suspend fun handle(line: String, writer: BufferedWriter, reader: BufferedReader) {
        val cmd = line.substringBefore(' ').uppercase()
        val args = line.substringAfter(' ', "").trim()
        if (expectAuthenticateNext && cmd != "AUTHENTICATE" && cmd != "QUIT") {
            reply(writer, "514 Authentication required after AUTHCHALLENGE")
            socket.close()
            return
        }
        when (cmd) {
            "PROTOCOLINFO" -> {
                reply(writer, "250-PROTOCOLINFO 1")
                reply(writer, "250-AUTH ${authMethodsLine()}")
                reply(writer, "250-VERSION Tor=\"kotlin-tor-0.1.0\"")
                reply(writer, "250 OK")
            }
            "AUTHCHALLENGE" -> handleAuthChallenge(args, writer)
            "AUTHENTICATE" -> handleAuthenticate(args, writer)
            "QUIT" -> {
                reply(writer, "250 closing connection")
                socket.close()
            }
            else -> {
                if (!authenticated) {
                    reply(writer, "514 Authentication required")
                    return
                }
                when (cmd) {
                    "GETINFO" -> handleGetInfo(args, writer)
                    "SETEVENTS" -> {
                        events.clear()
                        events.addAll(args.split(Regex("\\s+")).filter { it.isNotEmpty() }.map { it.uppercase() })
                        reply(writer, "250 OK")
                    }
                    "SIGNAL" -> handleSignal(args.uppercase(), writer)
                    "ADD_ONION" -> handleAddOnion(args, writer)
                    "DEL_ONION" -> handleDelOnion(args, writer)
                    "HSFETCH" -> handleHsFetch(args, writer)
                    "HSPOST" -> handleHsPost(args, writer, reader)
                    "SETCONF" -> handleSetConf(args, writer, reset = false)
                    "RESETCONF" -> handleSetConf(args, writer, reset = true)
                    "SAVECONF" -> {
                        // Persist runtime overrides beside the data directory (best-effort).
                        val f = daemon.config.dataDirectory.resolve("kotlin-tor-setconf")
                        Files.writeString(
                            f,
                            daemon.runtimeOverrides.entries.joinToString("\n") { "${it.key} ${it.value}" } +
                                if (daemon.runtimeOverrides.isNotEmpty()) "\n" else "",
                        )
                        reply(writer, "250 OK")
                    }
                    else -> reply(writer, "510 Unrecognized command")
                }
            }
        }
    }

    private suspend fun handleAuthChallenge(args: String, writer: BufferedWriter) {
        if (authchallengeUsed) {
            reply(writer, "514 AUTHCHALLENGE may only be used once")
            socket.close()
            return
        }
        if (!daemon.config.cookieAuthentication || !Files.exists(daemon.controlCookiePath)) {
            reply(writer, "515 Cookie authentication is disabled")
            socket.close()
            return
        }
        val parts = args.split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.size < 2 || !parts[0].equals("SAFECOOKIE", ignoreCase = true)) {
            reply(writer, "513 AUTHCHALLENGE only supports SAFECOOKIE authentication")
            socket.close()
            return
        }
        val clientNonce = try {
            decodeAuthBlob(parts[1])
        } catch (e: Exception) {
            reply(writer, "513 Invalid client nonce")
            socket.close()
            return
        }
        if (clientNonce.isEmpty()) {
            reply(writer, "513 Invalid client nonce")
            socket.close()
            return
        }
        val cookie = Files.readAllBytes(daemon.controlCookiePath)
        val serverNonce = SecureRandomSource.nextBytes(ControlCookie.SERVER_NONCE_LEN)
        val serverHash = ControlCookie.serverHash(cookie, clientNonce, serverNonce)
        safecookieClientHash = ControlCookie.clientHash(cookie, clientNonce, serverNonce)
        authchallengeUsed = true
        expectAuthenticateNext = true
        reply(
            writer,
            "250 AUTHCHALLENGE SERVERHASH=${serverHash.toHex()} SERVERNONCE=${serverNonce.toHex()}",
        )
    }

    private fun authMethodsLine(): String {
        val methods = mutableListOf<String>()
        if (daemon.config.cookieAuthentication) {
            methods += "COOKIE"
            methods += "SAFECOOKIE"
        }
        if (!daemon.config.hashedControlPassword.isNullOrBlank()) {
            methods += "HASHEDPASSWORD"
        }
        if (methods.isEmpty()) methods += "NULL"
        val base = "METHODS=" + methods.joinToString(",")
        return if (daemon.config.cookieAuthentication) {
            "$base COOKIEFILE=\"${daemon.controlCookiePath}\""
        } else {
            base
        }
    }

    private suspend fun handleAuthenticate(args: String, writer: BufferedWriter) {
        expectAuthenticateNext = false
        val hashed = daemon.config.hashedControlPassword
        val cookieAuth = daemon.config.cookieAuthentication
        if (args.isEmpty() && !cookieAuth && hashed.isNullOrBlank()) {
            authenticated = true
            connHandle.authenticated = true
            safecookieClientHash = null
            reply(writer, "250 OK")
            return
        }

        // Quoted password → HASHEDPASSWORD (or empty NULL).
        val trimmed = args.trim()
        if (trimmed.startsWith('"')) {
            val password = decodeQuotedString(trimmed)
            if (!hashed.isNullOrBlank() && ControlS2k.verify(password, hashed)) {
                authenticated = true
                connHandle.authenticated = true
                safecookieClientHash = null
                reply(writer, "250 OK")
            } else if (hashed.isNullOrBlank() && !cookieAuth) {
                authenticated = true
                connHandle.authenticated = true
                reply(writer, "250 OK")
            } else {
                reply(writer, "515 Authentication failed: Password did not match HashedControlPassword")
                socket.close()
            }
            return
        }

        val provided = try {
            decodeAuthBlob(trimmed)
        } catch (_: Exception) {
            reply(writer, "515 Authentication failed: Invalid hexadecimal encoding")
            socket.close()
            return
        }
        val expectedSafe = safecookieClientHash
        if (expectedSafe != null) {
            if (constantTimeEquals(provided, expectedSafe)) {
                authenticated = true
                connHandle.authenticated = true
                safecookieClientHash = null
                reply(writer, "250 OK")
            } else {
                reply(writer, "515 Authentication failed: Safe cookie response did not match")
                socket.close()
            }
            return
        }
        if (cookieAuth && Files.exists(daemon.controlCookiePath)) {
            val cookie = Files.readAllBytes(daemon.controlCookiePath)
            if (constantTimeEquals(provided, cookie)) {
                authenticated = true
                connHandle.authenticated = true
                reply(writer, "250 OK")
                return
            }
        }
        if (!hashed.isNullOrBlank()) {
            // Hex-encoded password octets (unusual but allowed by control-spec).
            val password = provided.toString(StandardCharsets.UTF_8)
            if (ControlS2k.verify(password, hashed)) {
                authenticated = true
                connHandle.authenticated = true
                reply(writer, "250 OK")
                return
            }
        }
        if (!cookieAuth && hashed.isNullOrBlank()) {
            authenticated = true
            connHandle.authenticated = true
            reply(writer, "250 OK")
            return
        }
        reply(writer, "515 Authentication failed")
        socket.close()
    }

    /** Hex (optional 0x) or quoted string blob for AUTHENTICATE / AUTHCHALLENGE. */
    private fun decodeAuthBlob(raw: String): ByteArray {
        val t = raw.trim()
        if (t.startsWith('"')) {
            return decodeQuotedString(t).toByteArray(StandardCharsets.UTF_8)
        }
        val hex = t.removePrefix("0x").removePrefix("0X").replace(" ", "")
        return hexToBytes(hex)
    }

    private fun decodeQuotedString(raw: String): String {
        require(raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2) {
            "quoted string required"
        }
        // Minimal C-style escapes used by controllers.
        val body = raw.substring(1, raw.length - 1)
        val out = StringBuilder()
        var i = 0
        while (i < body.length) {
            val c = body[i]
            if (c == '\\' && i + 1 < body.length) {
                when (val n = body[i + 1]) {
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    't' -> out.append('\t')
                    '"', '\\' -> out.append(n)
                    else -> out.append(n)
                }
                i += 2
            } else {
                out.append(c)
                i++
            }
        }
        return out.toString()
    }

    private suspend fun handleGetInfo(args: String, writer: BufferedWriter) {
        val keys = args.split(Regex("\\s+")).filter { it.isNotEmpty() }
        var failed = false
        for (key in keys) {
            when (key) {
                "version" -> reply(writer, "250-$key=kotlin-tor 0.1.0")
                "status/bootstrap-phase" ->
                    reply(writer, "250-$key=${daemon.client.bootstrapTracker.statusLine}")
                "status/circuit-established" ->
                    reply(writer, "250-$key=${if (daemon.client.hasCircuit) "1" else "0"}")
                "circuit-status" -> {
                    val lines = daemon.client.circuitStatusLines()
                    if (lines.isEmpty()) {
                        reply(writer, "250-$key=")
                    } else {
                        reply(writer, "250+$key=")
                        for (line in lines) reply(writer, line)
                        reply(writer, ".")
                    }
                }
                "net/listeners/socks" -> {
                    val socks = daemon.config.socksPorts.joinToString(" ") { "\"$it\"" }
                    reply(writer, "250-$key=$socks")
                }
                "net/listeners/control" -> {
                    val ctrl = daemon.config.controlPorts.joinToString(" ") { "\"$it\"" }
                    reply(writer, "250-$key=$ctrl")
                }
                "config-file" -> reply(writer, "250-$key=")
                "exit-policy/default" -> reply(writer, "250-$key=reject *:*")
                "onions/current" -> {
                    val ids = daemon.onionServices.list()
                        .joinToString(",") { it.address.removeSuffix(".onion") }
                    reply(writer, "250-$key=$ids")
                }
                "onions/detached" -> reply(writer, "250-$key=")
                "entry-guards" -> {
                    val lines = daemon.client.sampledGuardStatusLines()
                    if (lines.isEmpty()) reply(writer, "250-$key=")
                    else {
                        reply(writer, "250+$key=")
                        for (line in lines) reply(writer, line)
                        reply(writer, ".")
                    }
                }
                else -> {
                    if (key.startsWith("config/", ignoreCase = true)) {
                        val confKey = key.removePrefix("config/")
                        val v = daemon.confValue(confKey) ?: ""
                        reply(writer, "250-$key=$v")
                    } else {
                        reply(writer, "552 Unrecognized key \"$key\"")
                        failed = true
                    }
                }
            }
        }
        if (!failed) reply(writer, "250 OK")
    }

    private suspend fun handleSetConf(args: String, writer: BufferedWriter, reset: Boolean) {
        // SETCONF key=value key2="quoted value"
        if (args.isBlank()) {
            reply(writer, "250 OK")
            return
        }
        val tokens = tokenizeConfArgs(args)
        for (tok in tokens) {
            val key = tok.substringBefore('=').trim().uppercase()
            val value = tok.substringAfter('=', "").trim().removeSurrounding("\"")
            if (key.isEmpty()) {
                reply(writer, "512 Invalid SETCONF")
                return
            }
            if (reset || value.isEmpty()) {
                daemon.runtimeOverrides.remove(key)
            } else {
                daemon.runtimeOverrides[key] = value
            }
        }
        reply(writer, "250 OK")
    }

    private fun tokenizeConfArgs(args: String): List<String> {
        val out = mutableListOf<String>()
        var i = 0
        while (i < args.length) {
            while (i < args.length && args[i].isWhitespace()) i++
            if (i >= args.length) break
            if (args[i] == '"') {
                i++
                val sb = StringBuilder()
                while (i < args.length && args[i] != '"') {
                    if (args[i] == '\\' && i + 1 < args.length) {
                        sb.append(args[++i]); i++
                    } else {
                        sb.append(args[i++])
                    }
                }
                if (i < args.length && args[i] == '"') i++
                out += sb.toString()
            } else {
                val start = i
                while (i < args.length && !args[i].isWhitespace()) i++
                out += args.substring(start, i)
            }
        }
        // Merge KEY= and "value" split forms: KEY=value already one token.
        return out
    }

    private suspend fun handleSignal(sig: String, writer: BufferedWriter) {
        when (sig) {
            "NEWNYM" -> daemon.signalNewnym()
            "DORMANT" -> daemon.signalDormant()
            "ACTIVE" -> daemon.signalActive()
            "RELOAD", "HALT", "SHUTDOWN" -> Unit
            "CLEARDNSCACHE" -> Unit
            else -> {
                reply(writer, "552 Unrecognized signal")
                return
            }
        }
        reply(writer, "250 OK")
    }

    private suspend fun handleAddOnion(args: String, writer: BufferedWriter) {
        // ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:8080
        val ports = mutableListOf<Pair<Int, String>>()
        for (part in args.split(Regex("\\s+"))) {
            if (part.startsWith("Port=", ignoreCase = true)) {
                val body = part.substringAfter('=')
                val vp = body.substringBefore(',').toInt()
                val target = body.substringAfter(',', "127.0.0.1:$vp")
                ports += vp to target
            }
        }
        if (ports.isEmpty()) {
            reply(writer, "512 Invalid ADD_ONION")
            return
        }
        val inst = daemon.onionServices.addOnion(ports)
        // Background: establish intros + publish when circuit builder is wired.
        daemon.scope.launch {
            runCatching {
                daemon.onionServices.establishIntroPoints(inst)
                daemon.onionServices.publish(inst)
            }.onFailure {
                System.err.println("ADD_ONION publish: ${it.message}")
            }
        }
        reply(writer, "250-ServiceID=${inst.address.removeSuffix(".onion")}")
        reply(writer, "250 OK")
    }

    private suspend fun handleDelOnion(args: String, writer: BufferedWriter) {
        val id = args.trim().substringBefore(' ')
        if (id.isEmpty()) {
            reply(writer, "512 Invalid DEL_ONION")
            return
        }
        if (!daemon.onionServices.delOnion(id)) {
            reply(writer, "552 Unknown onion service")
            return
        }
        reply(writer, "250 OK")
    }

    private suspend fun handleHsFetch(args: String, writer: BufferedWriter) {
        // HSFETCH v3address [SERVER=…]
        val onion = args.trim().substringBefore(' ').trim()
        if (onion.isEmpty() || !org.kotlintor.hs.HsControl.hsFetchAccepted(onion)) {
            reply(writer, "512 Invalid HSFETCH")
            return
        }
        try {
            val addr = if (onion.endsWith(".onion")) onion else "$onion.onion"
            daemon.emit(org.kotlintor.TorEvent.HsDesc(
                org.kotlintor.hs.HsControl.descEventRequested(addr, "unknown", "HSDir"),
            ))
            val desc = daemon.client.fetchOnionDescriptor(addr)
            org.kotlintor.hs.HsMetrics.noteDescFetch()
            daemon.emit(org.kotlintor.TorEvent.HsDesc(
                org.kotlintor.hs.HsControl.descEventReceived(addr, "HSDir"),
            ))
            reply(writer, "250+hsdesc=$addr")
            for (line in desc.lineSequence()) reply(writer, line)
            reply(writer, ".")
            reply(writer, "250 OK")
        } catch (e: Exception) {
            val addr = if (onion.endsWith(".onion")) onion else "$onion.onion"
            daemon.emit(org.kotlintor.TorEvent.HsDesc(
                org.kotlintor.hs.HsControl.descEventFailed(addr, "HSDir", e.message ?: "error"),
            ))
            reply(writer, "551 Unable to fetch HS descriptor: ${e.message}")
        }
    }

    private suspend fun handleHsPost(args: String, writer: BufferedWriter, reader: BufferedReader) {
        // HSPOST [Server=<HSAddress>] then multiline: +\n<body>\n.
        var serverHint: String? = null
        for (tok in args.split(Regex("\\s+")).filter { it.isNotEmpty() }) {
            if (tok.startsWith("Server=", ignoreCase = true)) {
                serverHint = tok.substringAfter('=')
            }
        }
        val plus = reader.readLine()?.trim()
        if (plus != "+") {
            reply(writer, "512 HSPOST requires + multiline body")
            return
        }
        val body = StringBuilder()
        while (true) {
            val line = reader.readLine() ?: break
            if (line == ".") break
            body.append(line).append('\n')
        }
        val document = body.toString()
        if (!org.kotlintor.hs.HsControl.hsPostAccepted(document, serverHint)) {
            reply(writer, "512 Empty HSPOST body")
            return
        }
        try {
            val blinded = Regex("""(?m)^hs_blinded_id=(\S+)""")
                .find(document)?.groupValues?.get(1)
                ?.let { runCatching { java.util.Base64.getDecoder().decode(it) }.getOrNull() }
                ?: ByteArray(32)
            val blindedB64 = java.util.Base64.getEncoder().withoutPadding().encodeToString(blinded)
            val onion = serverHint ?: "unknown.onion"
            daemon.emit(org.kotlintor.TorEvent.HsDesc(
                org.kotlintor.hs.HsControl.descEventUpload(onion, "HSDir", blindedB64),
            ))
            val n = daemon.client.publishOnionDescriptor(document, blinded)
            org.kotlintor.hs.HsMetrics.noteDescUpload()
            daemon.emit(org.kotlintor.TorEvent.HsDesc(
                org.kotlintor.hs.HsControl.descEventUploaded(onion, "HSDir"),
            ))
            reply(writer, "250 OK")
            daemon.emit(org.kotlintor.TorEvent.Notice("HSPOST published to $n HSDirs server=$serverHint"))
        } catch (e: Exception) {
            reply(writer, "551 Unable to post HS descriptor: ${e.message}")
        }
    }

    private suspend fun reply(writer: BufferedWriter, line: String) = writeAsync(writer, "$line\r\n")
}
