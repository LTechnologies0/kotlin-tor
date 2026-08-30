package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys

class HsCellEstablishIntroTest {
    @Test
    fun `build and verify ESTABLISH_INTRO matches rend-spec layout`() {
        val kp = Ed25519Keys.generate()
        val kh = ByteArray(20) { 0xab.toByte() }
        val cell = HsCell.hsCellBuildEstablishIntro(kp.publicKey, kp.privateKey, kh, 10, 20)
        assertEquals(HsCell.AUTH_KEY_TYPE_ED25519, cell[0].toInt() and 0xff)
        assertEquals(32, HsIntropoint.getAuthKeyFromCell(cell)!!.size)
        assertTrue(HsIntropoint.verifyEstablishIntroCell(cell, kh))
        assertFalse(HsIntropoint.verifyEstablishIntroCell(cell, ByteArray(20)))
        val parsed = HsCell.parseEstablishIntro(cell)!!
        assertEquals(32, parsed.handshakeMac.size)
        assertEquals(64, parsed.signature.size)
    }
}
