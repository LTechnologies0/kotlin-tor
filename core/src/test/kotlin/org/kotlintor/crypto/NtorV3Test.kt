package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

class NtorV3Test {
    @Test
    fun `arti c-tor test vector`() {
        val bSk = hexToBytes("4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a")
        val bPk = Curve25519.publicFromPrivate(bSk)
        assertArrayEquals(
            hexToBytes("f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d"),
            bPk,
        )
        val id = hexToBytes("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2")
        val xSk = hexToBytes("b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49")
        val ySk = hexToBytes("4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053")
        val clientMessage = hexToBytes("68656c6c6f20776f726c64")
        val verification = hexToBytes("78797a7a79")
        val serverMessage = hexToBytes("486f6c61204d756e646f")

        val relay = NtorV3.PublicKey(id, bPk)
        val (state, clientHs) = NtorV3.clientBegin(relay, clientMessage, verification, xSk)
        assertEquals(
            "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2" +
                "f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d" +
                "252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f46" +
                "3bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c" +
                "72b68cd461942088502f67",
            clientHs.joinToString("") { "%02x".format(it) },
        )

        val server = NtorV3.serverRespond(
            id = id,
            onionSk = bSk,
            onionPk = bPk,
            clientHandshake = clientHs,
            serverMessage = serverMessage,
            verification = verification,
            serverYSk = ySk,
        )
        assertArrayEquals(clientMessage, server.clientMessage)
        assertEquals(
            "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d" +
                "2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a9127665" +
                "1202c3e1e87c0d32054c",
            server.handshake.joinToString("") { "%02x".format(it) },
        )

        val finished = NtorV3.clientFinish(state, server.handshake)
        assertArrayEquals(serverMessage, finished.serverMessage)
        assertArrayEquals(server.keystream, finished.keystream)
        assertEquals(
            "9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3b" +
                "feaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1" +
                "b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bd" +
                "e025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984c" +
                "aa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b0" +
                "9749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5" +
                "618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f2" +
                "26b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a",
            finished.keystream.joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun `random round trip with empty extensions`() {
        val onion = Curve25519.generateKeyPair()
        val id = org.kotlintor.util.SecureRandomSource.nextBytes(32)
        val relay = NtorV3.PublicKey(id, onion.publicKey)
        val cm = NtorV3.emptyExtensions()
        // CC_FIELD_RESPONSE: N_EXTENSIONS=1, type=2, len=1, sendme_inc=31
        val serverMsg = byteArrayOf(1, 2, 1, 31)
        val (state, hs) = NtorV3.clientBegin(relay, cm)
        val server = NtorV3.serverRespond(id, onion.privateKey, onion.publicKey, hs, serverMsg)
        assertArrayEquals(cm, server.clientMessage)
        val finished = NtorV3.clientFinish(state, server.handshake)
        assertArrayEquals(serverMsg, finished.serverMessage)
        assertArrayEquals(server.keystream, finished.keystream)
    }
}
