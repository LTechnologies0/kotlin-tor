package org.kotlintor.net

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import java.nio.file.Path

class AppProtocolsTest {
    @Test
    fun `smtp reply and ehlo`() {
        val g = SmtpCodec.parseReplyLine("220 mail.example.com ESMTP")!!
        assertTrue(SmtpCodec.isGreeting(g))
        val ehlo = SmtpCodec.encodeCommand("EHLO", "client.local")
        assertEquals("EHLO client.local\r\n", ehlo.toString(Charsets.US_ASCII))
        val multi = SmtpCodec.parseReplyLine("250-SIZE 52428800")!!
        assertTrue(multi.continued)
        assertEquals(250, multi.code)
    }

    @Test
    fun `imap greeting and tagged`() {
        val g = ImapCodec.parseGreeting("* OK IMAP4rev1 ready")!!
        assertEquals(ImapCodec.Greeting.Kind.OK, g.kind)
        val r = ImapCodec.parseTagged("a001 OK LOGIN completed")!!
        assertEquals("a001", r.tag)
        assertEquals("OK", r.status)
    }

    @Test
    fun `pop3 ok err`() {
        assertTrue(Pop3Codec.parseLine("+OK ready")!!.first)
        assertFalse(Pop3Codec.parseLine("-ERR lock")!!.first)
    }

    @Test
    fun `ftp port pasv eprt epsv`() {
        val port = FtpCodec.parsePortCommand("PORT 192,168,1,2,4,1")!!
        assertEquals("192.168.1.2", port.host)
        assertEquals(4 * 256 + 1, port.port)
        val pasv = FtpCodec.parsePasv227("227 Entering Passive Mode (10,0,0,1,195,80).")!!
        assertEquals("10.0.0.1", pasv.host)
        assertEquals(195 * 256 + 80, pasv.port)
        val eprt = FtpCodec.parseEprt("EPRT |1|132.235.1.2|6275|")!!
        assertEquals("132.235.1.2", eprt.host)
        assertEquals(6275, eprt.port)
        assertEquals(6446, FtpCodec.parseEpsv229("229 Entering Extended Passive Mode (|||6446|)"))
    }

    @Test
    fun `ssh ident`() {
        val id = SshIdent.parse("SSH-2.0-OpenSSH_9.0")!!
        assertEquals("2.0", id.proto)
        assertEquals("OpenSSH_9.0", id.software)
        assertTrue(SshIdent.looksLike("SSH-".toByteArray()))
    }

    @Test
    fun `mapaddress exact and wildcard`() {
        val rules = MapAddress.parseRules(
            listOf(
                "www.torproject.org 198.51.100.1",
                "*.example.com www.example.com",
            ),
        )
        assertEquals("198.51.100.1", MapAddress.apply("www.torproject.org", rules))
        assertEquals("www.example.com", MapAddress.apply("foo.example.com", rules))
    }

    @Test
    fun `longLivedPorts and mapaddress torrc`() {
        val cfg = TorrcParser.parse(
            """
            LongLivedPorts 22, 443, 993
            MapAddress check.torproject.org 127.0.0.1
            """.trimIndent(),
            Path.of("/tmp/d"),
        )
        assertEquals(setOf(22, 443, 993), cfg.longLivedPorts)
        assertTrue(cfg.isLongLivedPort(22))
        assertFalse(cfg.isLongLivedPort(80))
        assertEquals("check.torproject.org" to "127.0.0.1", cfg.mapAddress.first())
        assertEquals(TorConfig.DEFAULT_LONG_LIVED_PORTS, TorConfig(Path.of("/tmp/x")).longLivedPorts)
    }

    @Test
    fun `nntp reply and dot stuffing`() {
        val g = NntpCodec.parseReplyLine("200 NNTP Service Ready, posting allowed")!!
        assertTrue(NntpCodec.isGreeting(g))
        assertEquals("..hidden", NntpCodec.stuffLine(".hidden"))
        assertEquals(".hidden", NntpCodec.unstuffLine("..hidden"))
        assertEquals(null, NntpCodec.unstuffLine("."))
        val block = NntpCodec.decodeBlock(listOf("hello", "..dot", "."))
        assertEquals(listOf("hello", ".dot"), block)
    }

    @Test
    fun `irc message parse encode`() {
        val m = IrcCodec.parse(":nick!u@h PRIVMSG #chan :hello world")!!
        assertEquals("nick!u@h", m.prefix)
        assertEquals("PRIVMSG", m.command)
        assertEquals(listOf("#chan", "hello world"), m.params)
        val back = IrcCodec.encode(m.prefix, m.command, m.params).toString(Charsets.US_ASCII)
        assertEquals(":nick!u@h PRIVMSG #chan :hello world\r\n", back)
        val num = IrcCodec.parse(":irc.example 001 me :Welcome")!!
        assertTrue(num.isNumeric)
    }

    @Test
    fun `ftp tor rewrite pasv and port`() {
        val pasv = FtpTorRewrite.rewriteServerPasv227(
            "227 Entering Passive Mode (10,0,0,1,195,80).",
            "127.0.0.1",
            40000,
        )!!
        assertEquals("10.0.0.1", (pasv.torDial as NetEndpoint.Domain).name)
        assertEquals(195 * 256 + 80, pasv.torDial.port)
        assertTrue(pasv.rewrittenLine.contains("127,0,0,1,156,64"))
        val port = FtpTorRewrite.rewriteClientPort("PORT 192,168,1,2,4,1", "127.0.0.1", 40001)!!
        assertEquals(4 * 256 + 1, (port.torDial as NetEndpoint.Domain).port)
    }

    @Test
    fun `protocol peek`() {
        assertEquals(ProtocolPeek.Kind.Socks5, ProtocolPeek.classify(byteArrayOf(0x05, 0x01, 0x00)))
        assertEquals(ProtocolPeek.Kind.Tls, ProtocolPeek.classify(byteArrayOf(0x16, 0x03, 0x01)))
        assertEquals(ProtocolPeek.Kind.Http, ProtocolPeek.classify("CONNECT example.com:443 HTTP/1.1\r\n".toByteArray()))
        assertEquals(ProtocolPeek.Kind.Ssh, ProtocolPeek.classify("SSH-2.0-OpenSSH\r\n".toByteArray()))
        assertEquals(ProtocolPeek.Kind.Nntp, ProtocolPeek.classify("200 posting allowed\r\n".toByteArray()))
        assertEquals(ProtocolPeek.Kind.Smtp, ProtocolPeek.classify("220 mail ESMTP\r\n".toByteArray()))
        assertEquals(ProtocolPeek.Kind.Irc, ProtocolPeek.classify("NICK alice\r\n".toByteArray()))
        val mqtt = MqttCodec.encodeFixedHeader(MqttCodec.PacketType.Connect, 0, 10) + ByteArray(10)
        assertEquals(ProtocolPeek.Kind.Mqtt, ProtocolPeek.classify(mqtt))
        assertEquals(ProtocolPeek.Kind.Ldap, ProtocolPeek.classify(LdapBer.wrapSequence(byteArrayOf(0x02, 0x01, 0x01))))
        assertEquals(
            ProtocolPeek.Kind.Xmpp,
            ProtocolPeek.classify("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='ex.com'>".toByteArray()),
        )
    }

    @Test
    fun `mqtt remaining length roundtrip`() {
        for (n in listOf(0, 127, 128, 16383, 16384)) {
            val enc = MqttCodec.encodeRemainingLength(n)
            val (dec, used) = MqttCodec.decodeRemainingLength(enc)!!
            assertEquals(n, dec)
            assertEquals(enc.size, used)
        }
        val hdr = MqttCodec.parseFixedHeader(MqttCodec.encodeFixedHeader(MqttCodec.PacketType.Pingreq, 0, 0))!!
        assertEquals(MqttCodec.PacketType.Pingreq, hdr.type)
    }

    @Test
    fun `ldap ber frame`() {
        val inner = byteArrayOf(0x02, 0x01, 0x01)
        val msg = LdapBer.wrapSequence(inner)
        val (frame, consumed) = LdapBer.parseFrame(msg)!!
        assertEquals(0x30, frame.tag)
        assertTrue(frame.content.contentEquals(inner))
        assertEquals(msg.size, consumed)
    }

    @Test
    fun `xmpp stream open`() {
        val open = XmppStream.parseOpen(
            "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>",
        )!!
        assertEquals("example.com", open.to)
        assertEquals("1.0", open.version)
    }

    @Test
    fun `ftp control filter rewrites pasv`() {
        var seen: FtpTorRewrite.DataChannelNeed? = null
        val f = FtpControlFilter(
            advertiseHost = "127.0.0.1",
            allocateLocalPort = { 41000 },
            remoteHostHint = "ftp.example",
            onDataChannel = { seen = it },
        )
        val out = f.filterServerToClient("227 Entering Passive Mode (1,2,3,4,5,6).")
        assertNotNull(seen)
        assertTrue(out.contains("127,0,0,1"))
        assertEquals(5 * 256 + 6, (seen!!.torDial as NetEndpoint.Domain).port)
    }
}
