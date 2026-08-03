package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Shake256
import org.kotlintor.util.concat
import org.kotlintor.util.hexToBytes

class HsNtorTest {
    @Test
    fun `hs_mac matches arti vectors`() {
        assertEquals(
            "5e7da329630fdaa3eab7498bb1dc625bbb9ca968f10392b6af92d51d5db17473",
            HsNtor.hsMac("who".toByteArray(), "knows?".toByteArray()).toHex(),
        )
        assertEquals(
            "90071aabb06d3f7c777db41542f4790c7dd9e2e7b2b842f54c9c42bbdb37e9a0",
            HsNtor.hsMac("gone".toByteArray(), "by".toByteArray()).toHex(),
        )
        assertEquals(
            "753fba6d87d49497238a512a3772dd291e55f7d1cd332c9fb5c967c7a10a13ca",
            HsNtor.hsMac(
                "i'm from the past talking to the future.".toByteArray(),
                "i am in a library somewhere using my computer".toByteArray(),
            ).toHex(),
        )
    }

    @Test
    fun `chutney hs-ntor introduce + rendezvous vectors`() {
        val authKey = hexToBytes("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
        val subcred = hexToBytes("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")
        val encKey = hexToBytes("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
        val keyX = hexToBytes("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
        val introHeader = hexToBytes(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF" +
                "21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00",
        )
        val introBody = hexToBytes(
            "6BD364C12638DD5C3BE23D76ACA05B04E6CE932C0101000100200DE6130E4FCA" +
                "C4EDDA24E21220CC3EADAE403EF6B7D11C8273AC71908DE565450300067F0000" +
                "0113890214F823C4F8CC085C792E0AEE0283FE00AD7520B37D0320728D5DF39B" +
                "7B7077A0118A900FF4456C382F0041300ACF9C58E51C392795EF870000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000000000000000000000000000000000000",
        )
        val state = HsNtor.clientBegin(encKey, authKey, subcred, clientSk = keyX)
        val encrypted = HsNtor.clientEncryptIntro(state, introHeader, introBody, targetLen = 0)
        val cell = concat(introHeader, encrypted)
        val expected = hexToBytes(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF" +
                "21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED" +
                "726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E37830" +
                "4DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530" +
                "563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E8" +
                "3F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C" +
                "7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E" +
                "35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25D" +
                "DEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2" +
                "D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8",
        )
        assertArrayEquals(expected, cell)

        val reply = hexToBytes(
            "8fbe0db4d4a9c7ff46701e3e0ee7fd05cd28be4f302460addeec9e93354ee700" +
                "4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208",
        )
        val keys = HsNtor.clientFinishRendezvous(state, reply)
        val seed = hexToBytes("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")
        val expandConst = "tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand".toByteArray()
        val expectedMaterial = Shake256.xof(concat(seed, expandConst), 128)
        val got = concat(keys.forwardDigest, keys.backwardDigest, keys.forwardKey, keys.backwardKey)
        assertArrayEquals(expectedMaterial, got)
    }

    @Test
    fun `service decrypt intro round trip`() {
        val enc = org.kotlintor.crypto.Curve25519.generateKeyPair()
        val auth = org.kotlintor.crypto.Ed25519Keys.generate().publicKey
        val subcred = ByteArray(32) { 0x42 }
        val cookie = ByteArray(20) { 0x11 }
        val rendOnion = ByteArray(32) { 0x22 }
        val linkSpecs = listOf(
            byteArrayOf(0, 6, 1, 2, 3, 4, 0, 80),
            byteArrayOf(2, 20, *ByteArray(20) { 0x33 }),
        )
        val state = HsNtor.clientBegin(enc.publicKey, auth, subcred)
        val header = HsNtor.buildIntroHeader(auth)
        val plain = HsNtor.buildIntroducePlaintext(cookie, rendOnion, linkSpecs)
        val encrypted = HsNtor.clientEncryptIntro(state, header, plain, targetLen = 0)
        val ySk = org.kotlintor.crypto.Curve25519.generateKeyPair().privateKey
        val svc = HsNtor.serviceReceiveIntro(
            encPrivate = enc.privateKey,
            encPublic = enc.publicKey,
            authKey = auth,
            subcredential = subcred,
            introHeader = header,
            encrypted = encrypted,
            ephemeralSk = ySk,
        )
        assertArrayEquals(cookie, svc.plaintext.rendezvousCookie)
        assertArrayEquals(rendOnion, svc.plaintext.rendOnionKey)
        val clientKeys = HsNtor.clientFinishRendezvous(state, svc.handshakeInfo)
        // Service hop keys are swapped relative to the client.
        assertArrayEquals(clientKeys.forwardKey, svc.hopKeys.backwardKey)
        assertArrayEquals(clientKeys.backwardKey, svc.hopKeys.forwardKey)
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }
}
