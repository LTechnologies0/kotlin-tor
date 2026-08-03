package org.kotlintor.control

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.TorDaemon
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

class SafeCookieIntegrationTest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun `AUTHCHALLENGE SAFECOOKIE then AUTHENTICATE succeeds`() = runBlocking {
        val cookie = SecureRandomSource.nextBytes(32)
        Files.createDirectories(tmp)
        Files.write(tmp.resolve("control_auth_cookie"), cookie)

        val config = TorConfig(
            dataDirectory = tmp,
            controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
            socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
            cookieAuthentication = true,
        )
        val daemon = TorDaemon(config)
        val control = ControlServer(daemon, daemon.scope)
        control.start(config.controlPorts.first())
        delay(50)
        val port = control.boundPort()
        assertTrue(port > 0)

        Socket("127.0.0.1", port).use { sock ->
            val reader = BufferedReader(InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8))
            val writer = BufferedWriter(OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8))

            fun send(line: String) {
                writer.write(line)
                writer.write("\r\n")
                writer.flush()
            }

            fun readReply(): String {
                val lines = mutableListOf<String>()
                while (true) {
                    val line = reader.readLine() ?: break
                    lines += line
                    if (line.length >= 4 && line[3] == ' ') break
                }
                return lines.joinToString("\n")
            }

            send("PROTOCOLINFO 1")
            val proto = readReply()
            assertTrue(proto.contains("SAFECOOKIE"), proto)

            val clientNonce = SecureRandomSource.nextBytes(32)
            send("AUTHCHALLENGE SAFECOOKIE ${clientNonce.toHex()}")
            val challenge = readReply()
            assertTrue(challenge.startsWith("250 AUTHCHALLENGE"), challenge)
            val serverHashHex = Regex("SERVERHASH=([0-9A-Fa-f]+)").find(challenge)!!.groupValues[1]
            val serverNonceHex = Regex("SERVERNONCE=([0-9A-Fa-f]+)").find(challenge)!!.groupValues[1]
            val serverNonce = hexToBytes(serverNonceHex)
            val expectedServer = ControlCookie.serverHash(cookie, clientNonce, serverNonce)
            assertTrue(expectedServer.contentEquals(hexToBytes(serverHashHex)), "SERVERHASH mismatch")

            val clientHash = ControlCookie.clientHash(cookie, clientNonce, serverNonce)
            send("AUTHENTICATE ${clientHash.toHex()}")
            val auth = readReply()
            assertTrue(auth.startsWith("250"), auth)

            send("GETINFO version")
            val info = readReply()
            assertTrue(info.contains("250"), info)
        }

        control.stop()
        daemon.stop()
    }
}
