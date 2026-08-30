package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.keymgt.LoadKey
import java.nio.file.Files
import java.nio.file.Path

/**
 * Elevates `L1:feature/keymgt/loadkey.c` toward D3.
 *
 * Evidence: INIT_ED_KEY_* create/split/replace/missing-secret-ok.
 */
class LoadKeyElevationTest {
    @TempDir
    lateinit var dir: Path

    @Test
    fun `ed_key_init_from_file CREATE SPLIT roundtrip`() {
        val base = dir.resolve("ed25519_signing")
        val a = LoadKey.edKeyInitFromFile(
            base,
            LoadKey.INIT_ED_KEY_CREATE or LoadKey.INIT_ED_KEY_SPLIT,
        )
        assertNotNull(a)
        assertTrue(Files.exists(Path.of(base.toString() + "_secret_key")))
        assertTrue(Files.exists(Path.of(base.toString() + "_public_key")))
        val b = LoadKey.edKeyInitFromFile(base, LoadKey.INIT_ED_KEY_SPLIT)
        assertNotNull(b)
        assertTrue(a!!.privateKey.contentEquals(b!!.privateKey))
        assertTrue(a.publicKey.contentEquals(b.publicKey))
    }

    @Test
    fun `REPLACE creates new material`() {
        val base = dir.resolve("ed25519_id")
        val a = LoadKey.edKeyInitFromFile(base, LoadKey.INIT_ED_KEY_CREATE or LoadKey.INIT_ED_KEY_SPLIT)!!
        val b = LoadKey.edKeyInitFromFile(
            base,
            LoadKey.INIT_ED_KEY_CREATE or LoadKey.INIT_ED_KEY_REPLACE or LoadKey.INIT_ED_KEY_SPLIT,
        )!!
        assertFalse(a.privateKey.contentEquals(b.privateKey))
    }

    @Test
    fun `MISSING_SECRET_OK loads public only`() {
        val base = dir.resolve("ed25519_pub")
        val kp = LoadKey.edKeyNew()
        Files.write(Path.of(base.toString() + "_public_key"), kp.publicKey)
        val loaded = LoadKey.edKeyInitFromFile(base, LoadKey.INIT_ED_KEY_MISSING_SECRET_OK)
        assertNotNull(loaded)
        assertTrue(loaded!!.publicKey.contentEquals(kp.publicKey))
        assertEquals(32, LoadKey.publicFromSecret(kp.privateKey).size)
    }

    @Test
    fun `loadOrCreateEd25519Identity stable`() {
        val k1 = LoadKey.loadOrCreateEd25519Identity(dir.resolve("keys"))
        val k2 = LoadKey.loadOrCreateEd25519Identity(dir.resolve("keys"))
        assertTrue(k1.privateKey.contentEquals(k2.privateKey))
    }
}
