package org.kotlintor.demo

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path

/** Minimal control-spec client for demo GETINFO / SIGNAL (cookie AUTHENTICATE). */
object DemoControlClient {
    fun getInfo(host: String, port: Int, cookiePath: Path, keys: List<String>): String =
        session(host, port, cookiePath) { writer, reader ->
            val sb = StringBuilder()
            for (k in keys) {
                writer.write("GETINFO $k\r\n")
                writer.flush()
                sb.appendLine(readReply(reader))
            }
            sb.toString().trimEnd()
        }

    fun signal(host: String, port: Int, cookiePath: Path, signal: String): String =
        session(host, port, cookiePath) { writer, reader ->
            writer.write("SIGNAL $signal\r\n")
            writer.flush()
            readReply(reader)
        }

    private fun session(
        host: String,
        port: Int,
        cookiePath: Path,
        block: (BufferedWriter, BufferedReader) -> String,
    ): String {
        Socket().use { sock ->
            sock.soTimeout = 15_000
            sock.connect(InetSocketAddress(host, port), 10_000)
            val reader = BufferedReader(InputStreamReader(sock.getInputStream(), Charsets.US_ASCII))
            val writer = BufferedWriter(OutputStreamWriter(sock.getOutputStream(), Charsets.US_ASCII))
            readReply(reader)
            writer.write("PROTOCOLINFO 1\r\n")
            writer.flush()
            readReply(reader)
            val cookie = Files.readAllBytes(cookiePath)
            writer.write("AUTHENTICATE ${cookie.toHex()}\r\n")
            writer.flush()
            val auth = readReply(reader)
            if (!auth.contains("250")) error("AUTHENTICATE failed: $auth")
            val out = block(writer, reader)
            writer.write("QUIT\r\n")
            writer.flush()
            return out
        }
    }

    private fun readReply(reader: BufferedReader): String {
        val sb = StringBuilder()
        while (true) {
            val line = reader.readLine() ?: break
            sb.appendLine(line)
            if (line.length >= 4 && line[3] == ' ') break
        }
        return sb.toString().trimEnd()
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { b -> "%02X".format(b) }
}
