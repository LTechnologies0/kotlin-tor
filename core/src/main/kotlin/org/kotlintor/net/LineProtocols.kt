package org.kotlintor.net

/**
 * CRLF line reader over [BufferedBytePipe] for SMTP/FTP/NNTP/IRC control planes.
 */
class LineReader(
    private val pipe: BufferedBytePipe,
    private val maxLine: Int = 8192,
) {
    suspend fun readLine(): String? {
        val acc = ArrayList<Byte>(256)
        while (acc.size < maxLine) {
            val b = pipe.readByte()
            if (b < 0) {
                return if (acc.isEmpty()) null else acc.toByteArray().toString(Charsets.UTF_8)
            }
            if (b == '\n'.code) {
                // trim optional CR
                if (acc.isNotEmpty() && acc.last() == '\r'.code.toByte()) acc.removeAt(acc.lastIndex)
                return acc.toByteArray().toString(Charsets.UTF_8)
            }
            acc.add(b.toByte())
        }
        error("line exceeds $maxLine")
    }

    suspend fun writeLine(line: String) {
        val withCrLf = if (line.endsWith("\r\n")) line else "$line\r\n"
        pipe.write(withCrLf.toByteArray(Charsets.UTF_8))
    }
}

/**
 * Intercept FTP control lines and rewrite PORT/PASV/EPRT/EPSV for Tor data channels.
 * Non-matching lines pass through unchanged.
 */
class FtpControlFilter(
    private val advertiseHost: String,
    private val allocateLocalPort: () -> Int,
    private val remoteHostHint: String,
    private val onDataChannel: (FtpTorRewrite.DataChannelNeed) -> Unit,
) {
    fun filterClientToServer(line: String): String {
        val u = line.trim().uppercase()
        return when {
            u.startsWith("PORT ") -> {
                val port = allocateLocalPort()
                val need = FtpTorRewrite.rewriteClientPort(line, advertiseHost, port) ?: return line
                onDataChannel(need)
                need.rewrittenLine.trimEnd('\r', '\n')
            }
            u.startsWith("EPRT ") -> {
                val port = allocateLocalPort()
                val need = FtpTorRewrite.rewriteClientEprt(line, advertiseHost, port) ?: return line
                onDataChannel(need)
                need.rewrittenLine.trimEnd('\r', '\n')
            }
            else -> line
        }
    }

    fun filterServerToClient(line: String): String {
        val t = line.trim()
        return when {
            t.startsWith("227") -> {
                val port = allocateLocalPort()
                val need = FtpTorRewrite.rewriteServerPasv227(line, advertiseHost, port) ?: return line
                onDataChannel(need)
                need.rewrittenLine.trimEnd('\r', '\n')
            }
            t.startsWith("229") -> {
                val port = allocateLocalPort()
                val need = FtpTorRewrite.rewriteServerEpsv229(line, port, remoteHostHint) ?: return line
                onDataChannel(need)
                need.rewrittenLine.trimEnd('\r', '\n')
            }
            else -> line
        }
    }
}
