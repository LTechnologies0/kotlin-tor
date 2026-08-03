package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

class Ed25519BlindTest {
    @Test
    fun `arti C-tor private key blinding vectors`() {
        // From tor-llcrypto keymanip.rs blinding() (little-t-tor ed25519_exts_ref.py).
        val seckey = hexToBytes("26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36")
        val param = hexToBytes("54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823")
        val expectBlindedPub = hexToBytes("1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41")
        val expectBlindedSec = hexToBytes(
            "293c3acff4e902f6f63ddc5d5caa2a57e771db4f24de65d4c28df3232f47fa01" +
                "171d43f24e3f53e70ec7ac280044ac77d4942dee5d6807118a59bdf3ee647e89",
        )

        val expanded = Ed25519Blind.expandSecretKey(seckey)
        val blinded = Ed25519Blind.blindKeypair(expanded, param)
        assertArrayEquals(expectBlindedPub, blinded.publicKey)
        assertArrayEquals(expectBlindedSec, blinded.bytes)

        val pubPath = Ed25519Blind.blindPublicKey(expanded.publicKey, param)
        assertArrayEquals(expectBlindedPub, pubPath)

        val msg = "hello world".toByteArray()
        val sig = Ed25519Blind.signExpanded(blinded, msg)
        assertTrue(Ed25519Keys.verify(blinded.publicKey, msg, sig))
    }

    @Test
    fun `expanded seed matches generatePublicKey`() {
        val kp = Ed25519Keys.generate()
        val expanded = Ed25519Blind.expandSecretKey(kp.privateKey)
        assertArrayEquals(kp.publicKey, expanded.publicKey)
    }
}
