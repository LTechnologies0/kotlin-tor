package org.kotlintor.net

import java.nio.charset.StandardCharsets

/**
 * Line-oriented mail / FTP / SSH control codecs (RFC 5321, 3501, 1939, 959, 4253).
 * Pure parse — used to inspect/shape streams before or during Tor encapsulation.
 */
object SmtpCodec {
    data class Reply(val code: Int, val continued: Boolean, val text: String)

    /** Parse one SMTP reply line (`250-…` / `250 …`). */
    fun parseReplyLine(line: String): Reply? {
        val t = line.trimEnd('\r', '\n')
        if (t.length < 3 || !t.take(3).all { it.isDigit() }) return null
        val code = t.take(3).toInt()
        val cont = t.length > 3 && t[3] == '-'
        val text = if (t.length > 4) t.substring(4) else ""
        return Reply(code, cont, text)
    }

    fun encodeCommand(verb: String, arg: String? = null): ByteArray {
        val s = if (arg.isNullOrEmpty()) "$verb\r\n" else "$verb $arg\r\n"
        return s.toByteArray(StandardCharsets.US_ASCII)
    }

    fun isGreeting(reply: Reply): Boolean = reply.code == 220 && !reply.continued
    fun isEhloOk(reply: Reply): Boolean = reply.code == 250
}

object Pop3Codec {
    fun parseLine(line: String): Pair<Boolean, String>? {
        val t = line.trimEnd('\r', '\n')
        return when {
            t.startsWith("+OK") -> true to t.removePrefix("+OK").trimStart()
            t.startsWith("-ERR") -> false to t.removePrefix("-ERR").trimStart()
            else -> null
        }
    }

    fun encode(command: String, arg: String? = null): ByteArray {
        val s = if (arg.isNullOrEmpty()) "$command\r\n" else "$command $arg\r\n"
        return s.toByteArray(StandardCharsets.US_ASCII)
    }
}

object ImapCodec {
    data class Greeting(val kind: Kind, val text: String) {
        enum class Kind { OK, PREAUTH, BYE, OTHER }
    }

    data class Response(val tag: String, val status: String, val text: String)

    fun parseGreeting(line: String): Greeting? {
        val t = line.trimEnd('\r', '\n')
        if (!t.startsWith("* ")) return null
        val rest = t.removePrefix("* ").trimStart()
        val kind = when {
            rest.startsWith("OK", true) -> Greeting.Kind.OK
            rest.startsWith("PREAUTH", true) -> Greeting.Kind.PREAUTH
            rest.startsWith("BYE", true) -> Greeting.Kind.BYE
            else -> Greeting.Kind.OTHER
        }
        return Greeting(kind, rest)
    }

    fun parseTagged(line: String): Response? {
        val t = line.trimEnd('\r', '\n')
        val parts = t.split(' ', limit = 3)
        if (parts.size < 2) return null
        if (parts[0] == "*" || parts[0] == "+") return null
        return Response(parts[0], parts[1], parts.getOrElse(2) { "" })
    }

    fun encode(tag: String, command: String, args: String = ""): ByteArray {
        val s = if (args.isEmpty()) "$tag $command\r\n" else "$tag $command $args\r\n"
        return s.toByteArray(StandardCharsets.US_ASCII)
    }
}

/**
 * FTP control (RFC 959) PORT / PASV + RFC 2428 EPSV / EPRT.
 */
object FtpCodec {
    data class HostPort(val host: String, val port: Int)

    /** `PORT h1,h2,h3,h4,p1,p2` */
    fun parsePortCommand(line: String): HostPort? {
        val arg = line.trim().removePrefix("PORT").trim().removePrefix("port").trim()
        val parts = arg.split(',').map { it.trim() }
        if (parts.size != 6) return null
        val nums = parts.map { it.toIntOrNull() ?: return null }
        if (nums.any { it !in 0..255 }) return null
        val host = nums.take(4).joinToString(".")
        val port = nums[4] * 256 + nums[5]
        return HostPort(host, port)
    }

    fun encodePort(host: String, port: Int): String {
        val octets = host.split('.').map { it.toInt() }
        require(octets.size == 4)
        val p1 = port / 256
        val p2 = port % 256
        return "PORT ${octets.joinToString(",")},$p1,$p2\r\n"
    }

    /** `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).` */
    fun parsePasv227(line: String): HostPort? {
        val start = line.indexOf('(')
        val end = line.indexOf(')')
        if (start < 0 || end <= start) return null
        val inner = line.substring(start + 1, end)
        return parsePortCommand("PORT $inner")
    }

    /** `EPRT |1|132.235.1.2|6275|` or `|2|1080::8:800:200C:417A|5282|` */
    fun parseEprt(line: String): HostPort? {
        val arg = line.trim().removePrefix("EPRT").trim().removePrefix("eprt").trim()
        if (arg.length < 5) return null
        val d = arg[0]
        val parts = arg.trim(d).split(d)
        if (parts.size < 3) return null
        val host = parts[1]
        val port = parts[2].toIntOrNull() ?: return null
        return HostPort(host, port)
    }

    /** `229 Entering Extended Passive Mode (|||6446|)` */
    fun parseEpsv229(line: String): Int? {
        val start = line.indexOf('(')
        val end = line.indexOf(')')
        if (start < 0 || end <= start) return null
        val inner = line.substring(start + 1, end)
        val parts = inner.split('|').filter { it.isNotEmpty() }
        return parts.lastOrNull()?.toIntOrNull()
    }

    fun parseReplyCode(line: String): Int? {
        val t = line.trimEnd('\r', '\n')
        if (t.length < 3 || !t.take(3).all { it.isDigit() }) return null
        return t.take(3).toInt()
    }
}

/**
 * SSH protocol version exchange (RFC 4253 §4.2): `SSH-protoversion-softwareversion SP comments CR LF`
 */
object SshIdent {
    data class Ident(val proto: String, val software: String, val comment: String?)

    fun parse(line: String): Ident? {
        val t = line.trimEnd('\r', '\n')
        if (!t.startsWith("SSH-")) return null
        val body = t.removePrefix("SSH-")
        val sp = body.indexOf(' ')
        val main = if (sp < 0) body else body.substring(0, sp)
        val comment = if (sp < 0) null else body.substring(sp + 1)
        val dash = main.indexOf('-')
        if (dash < 0) return null
        return Ident(main.substring(0, dash), main.substring(dash + 1), comment)
    }

    fun looksLike(firstBytes: ByteArray): Boolean {
        if (firstBytes.size < 4) return false
        return firstBytes[0] == 'S'.code.toByte() &&
            firstBytes[1] == 'S'.code.toByte() &&
            firstBytes[2] == 'H'.code.toByte() &&
            firstBytes[3] == '-'.code.toByte()
    }

    fun encode(proto: String, software: String, comment: String? = null): ByteArray {
        val s = if (comment == null) "SSH-$proto-$software\r\n" else "SSH-$proto-$software $comment\r\n"
        return s.toByteArray(StandardCharsets.US_ASCII)
    }
}

/**
 * Destination rewrite (torrc MapAddress).
 * Last matching rule wins (C Tor evaluates until no match; we apply in order and keep last hit).
 */
object MapAddress {
    data class Rule(val from: String, val to: String)

    fun parseRules(lines: List<String>): List<Rule> =
        lines.mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size < 2) null else Rule(parts[0], parts[1])
        }

    fun apply(host: String, rules: List<Rule>): String {
        var cur = host
        var changed: Boolean
        var guard = 0
        do {
            changed = false
            for (r in rules) {
                val next = match(cur, r) ?: continue
                cur = next
                changed = true
            }
            guard++
        } while (changed && guard < 32)
        return cur
    }

    private fun match(host: String, rule: Rule): String? {
        val from = rule.from
        val to = rule.to
        return when {
            from.startsWith("*.") -> {
                val suffix = from.removePrefix("*") // ".example.com"
                val ok = host.endsWith(suffix, ignoreCase = true) ||
                    host.equals(suffix.removePrefix("."), ignoreCase = true)
                if (!ok) return null
                if (to.startsWith("*.")) {
                    val hostLeft = when {
                        host.endsWith(suffix, true) -> host.dropLast(suffix.length).trimEnd('.')
                        else -> ""
                    }
                    val toSuffix = to.removePrefix("*")
                    if (hostLeft.isEmpty()) toSuffix.removePrefix(".") else hostLeft + toSuffix
                } else {
                    to
                }
            }
            host.equals(from, ignoreCase = true) -> to
            else -> null
        }
    }
}
