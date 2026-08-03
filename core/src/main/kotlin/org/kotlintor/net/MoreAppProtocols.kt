package org.kotlintor.net

import java.nio.charset.StandardCharsets

/**
 * NNTP (RFC 3977): 3-digit replies, commands, and dot-stuffed multi-line blocks.
 */
object NntpCodec {
    data class Reply(val code: Int, val text: String) {
        val classDigit: Int get() = code / 100
        fun isMultilineHint(): Boolean =
            // ARTICLE/HEAD/BODY/LIST/… success codes that carry a following block (common set)
            code in setOf(100, 101, 211, 215, 220, 221, 222, 223, 224, 225, 230, 231)
    }

    fun parseReplyLine(line: String): Reply? {
        val t = line.trimEnd('\r', '\n')
        if (t.length < 3 || !t.take(3).all { it.isDigit() }) return null
        val code = t.take(3).toInt()
        val text = if (t.length > 4) t.substring(4) else ""
        return Reply(code, text)
    }

    fun isGreeting(reply: Reply): Boolean = reply.code == 200 || reply.code == 201

    fun encodeCommand(keyword: String, args: String = ""): ByteArray {
        val s = if (args.isEmpty()) "$keyword\r\n" else "$keyword $args\r\n"
        return s.toByteArray(StandardCharsets.UTF_8)
    }

    /** Undo RFC 3977 §3.1.1 dot-stuffing for one line (without CRLF). */
    fun unstuffLine(line: String): String? {
        if (line == ".") return null // terminator
        return if (line.startsWith(".")) line.substring(1) else line
    }

    /** Dot-stuff a content line (without CRLF). */
    fun stuffLine(line: String): String =
        if (line.startsWith(".")) ".$line" else line

    fun encodeBlock(lines: List<String>): ByteArray {
        val sb = StringBuilder()
        for (l in lines) {
            sb.append(stuffLine(l)).append("\r\n")
        }
        sb.append(".\r\n")
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    fun decodeBlock(rawLines: List<String>): List<String> {
        val out = ArrayList<String>()
        for (l in rawLines) {
            val u = unstuffLine(l.trimEnd('\r', '\n')) ?: break
            out += u
        }
        return out
    }
}

/**
 * IRC client protocol messages (RFC 2812 §2.3).
 * Messages are CRLF-delimited and ≤ 512 octets including CRLF.
 */
object IrcCodec {
    data class Message(
        val prefix: String?,
        val command: String,
        val params: List<String>,
    ) {
        val isNumeric: Boolean get() = command.length == 3 && command.all { it.isDigit() }
        val trailing: String? get() = params.lastOrNull()
    }

    fun parse(line: String): Message? {
        var s = line.trimEnd('\r', '\n')
        if (s.isEmpty()) return null
        var prefix: String? = null
        if (s.startsWith(":")) {
            val sp = s.indexOf(' ')
            if (sp < 0) return null
            prefix = s.substring(1, sp)
            s = s.substring(sp + 1).trimStart()
        }
        val sp = s.indexOf(' ')
        val command: String
        val rest: String
        if (sp < 0) {
            command = s
            rest = ""
        } else {
            command = s.substring(0, sp)
            rest = s.substring(sp + 1)
        }
        if (command.isEmpty()) return null
        val params = ArrayList<String>()
        var i = 0
        val r = rest
        while (i < r.length) {
            while (i < r.length && r[i] == ' ') i++
            if (i >= r.length) break
            if (r[i] == ':') {
                params += r.substring(i + 1)
                break
            }
            val next = r.indexOf(' ', i)
            if (next < 0) {
                params += r.substring(i)
                break
            }
            params += r.substring(i, next)
            i = next + 1
        }
        return Message(prefix, command, params)
    }

    fun encode(prefix: String?, command: String, params: List<String>): ByteArray {
        val sb = StringBuilder()
        if (prefix != null) sb.append(':').append(prefix).append(' ')
        sb.append(command)
        params.forEachIndexed { idx, p ->
            sb.append(' ')
            if (idx == params.lastIndex && (p.contains(' ') || p.startsWith(':'))) {
                sb.append(':').append(p)
            } else {
                sb.append(p)
            }
        }
        sb.append("\r\n")
        val bytes = sb.toString().toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= 512) { "IRC message > 512 octets" }
        return bytes
    }

    fun nick(nick: String): ByteArray = encode(null, "NICK", listOf(nick))
    fun user(user: String, mode: Int, realname: String): ByteArray =
        encode(null, "USER", listOf(user, mode.toString(), "*", realname))
    fun ping(token: String): ByteArray = encode(null, "PING", listOf(token))
    fun pong(token: String): ByteArray = encode(null, "PONG", listOf(token))
    fun privmsg(target: String, text: String): ByteArray =
        encode(null, "PRIVMSG", listOf(target, text))
}

/**
 * First-byte / greeting peek for protocol-aware Tor frontends.
 * Local TCP accept → classify → shape → Tor CONNECT.
 */
object ProtocolPeek {
    enum class Kind {
        Socks4,
        Socks5,
        Http,
        Tls,
        Smtp,
        Pop3,
        Imap,
        Ftp,
        Ssh,
        Nntp,
        Irc,
        Mqtt,
        Ldap,
        Xmpp,
        Http2,
        Redis,
        Postgres,
        Unknown,
    }

    fun classify(first: ByteArray): Kind {
        if (first.isEmpty()) return Kind.Unknown
        val b0 = first[0].toInt() and 0xff
        when (b0) {
            0x04 -> return Kind.Socks4
            0x05 -> return Kind.Socks5
            0x16 -> return Kind.Tls
            0x10 -> if (MqttCodec.looksLikeConnect(first)) return Kind.Mqtt
            0x30 -> if (LdapBer.looksLikeLdap(first)) return Kind.Ldap
        }
        if (Http2Codec.looksLikePreface(first)) return Kind.Http2
        if (XmppStream.looksLike(first)) return Kind.Xmpp
        if (PostgresStartup.looksLike(first)) return Kind.Postgres
        if (RedisResp.looksLike(first) && first[0] == '*'.code.toByte()) return Kind.Redis
        val ascii = first.toString(Charsets.US_ASCII)
        val line = ascii.substringBefore('\r').substringBefore('\n')
        val u = line.uppercase()
        return when {
            u.startsWith("GET ") || u.startsWith("POST ") || u.startsWith("HEAD ") ||
                u.startsWith("PUT ") || u.startsWith("DELETE ") || u.startsWith("OPTIONS ") ||
                u.startsWith("CONNECT ") || u.startsWith("PATCH ") ||
                u.startsWith("PRI ") -> Kind.Http
            u.startsWith("SSH-") -> Kind.Ssh
            u.startsWith("EHLO ") || u.startsWith("HELO ") -> Kind.Smtp
            u.startsWith("+OK") -> Kind.Pop3
            u.startsWith("* OK") || u.startsWith("* PREAUTH") || u.startsWith("* BYE") -> Kind.Imap
            u.startsWith("200 ") || u.startsWith("201 ") -> Kind.Nntp
            u.startsWith("220 ") || u.startsWith("220-") -> when {
                u.contains("ESMTP", true) || u.contains("SMTP", true) -> Kind.Smtp
                u.contains("FTP", true) -> Kind.Ftp
                else -> Kind.Smtp
            }
            u.startsWith(":") || u.startsWith("NICK ") || u.startsWith("USER ") ||
                u.startsWith("PASS ") || u.startsWith("CAP ") -> Kind.Irc
            u.length >= 4 && u.take(3).all { it.isDigit() } && u[3] == ' ' &&
                u.take(3).toInt() in 1..999 -> Kind.Irc
            else -> Kind.Unknown
        }
    }
}

/**
 * Rewrite FTP PORT/PASV/EPRT/EPSV so the *data* channel can be re-bound locally
 * and forwarded over a separate Tor CONNECT (RFC 959 + 2428).
 *
 * Pattern: control stream stays on one Tor circuit; on PASV/PORT the proxy opens
 * a local listener, rewrites the advertised endpoint to that listener, and when
 * the peer connects, dials the real data host:port via [TorRouteRequest].
 */
object FtpTorRewrite {
    data class DataChannelNeed(
        /** Real remote data endpoint to dial over Tor (PASV/EPSV case). */
        val torDial: NetEndpoint?,
        /** Local address to advertise to the FTP peer (client or server side). */
        val advertise: FtpCodec.HostPort,
        /** Rewritten control line to inject toward the peer. */
        val rewrittenLine: String,
        val mode: Mode,
    ) {
        enum class Mode { ActivePort, PassivePasv, ActiveEprt, PassiveEpsv }
    }

    /**
     * Client → server PORT: peer will dial [advertise]; we must accept locally then
     * Tor-CONNECT to the original PORT target (active mode).
     */
    fun rewriteClientPort(
        portLine: String,
        advertiseHost: String,
        advertisePort: Int,
    ): DataChannelNeed? {
        val orig = FtpCodec.parsePortCommand(portLine) ?: return null
        val line = FtpCodec.encodePort(advertiseHost, advertisePort)
        return DataChannelNeed(
            torDial = NetEndpoint.Domain(orig.host, orig.port),
            advertise = FtpCodec.HostPort(advertiseHost, advertisePort),
            rewrittenLine = line,
            mode = DataChannelNeed.Mode.ActivePort,
        )
    }

    /** Server → client 227 PASV: rewrite so client dials our local listener. */
    fun rewriteServerPasv227(
        pasvLine: String,
        advertiseHost: String,
        advertisePort: Int,
    ): DataChannelNeed? {
        val orig = FtpCodec.parsePasv227(pasvLine) ?: return null
        val octets = advertiseHost.split('.').map { it.toIntOrNull() ?: return null }
        if (octets.size != 4) return null
        val p1 = advertisePort / 256
        val p2 = advertisePort % 256
        val line = "227 Entering Passive Mode (${octets.joinToString(",")},$p1,$p2).\r\n"
        return DataChannelNeed(
            torDial = NetEndpoint.Domain(orig.host, orig.port),
            advertise = FtpCodec.HostPort(advertiseHost, advertisePort),
            rewrittenLine = line,
            mode = DataChannelNeed.Mode.PassivePasv,
        )
    }

    fun rewriteClientEprt(
        eprtLine: String,
        advertiseHost: String,
        advertisePort: Int,
        family: Int = 1,
    ): DataChannelNeed? {
        val orig = FtpCodec.parseEprt(eprtLine) ?: return null
        val line = "EPRT |$family|$advertiseHost|$advertisePort|\r\n"
        return DataChannelNeed(
            torDial = NetEndpoint.Domain(orig.host, orig.port),
            advertise = FtpCodec.HostPort(advertiseHost, advertisePort),
            rewrittenLine = line,
            mode = DataChannelNeed.Mode.ActiveEprt,
        )
    }

    fun rewriteServerEpsv229(
        epsvLine: String,
        advertisePort: Int,
        remoteHost: String,
    ): DataChannelNeed? {
        val origPort = FtpCodec.parseEpsv229(epsvLine) ?: return null
        val line = "229 Entering Extended Passive Mode (|||$advertisePort|)\r\n"
        return DataChannelNeed(
            torDial = NetEndpoint.Domain(remoteHost, origPort),
            advertise = FtpCodec.HostPort("0.0.0.0", advertisePort),
            rewrittenLine = line,
            mode = DataChannelNeed.Mode.PassiveEpsv,
        )
    }
}
