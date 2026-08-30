package org.kotlintor.keymgt

import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.link.OrCertMaterial
import java.nio.file.Files
import java.nio.file.Path

/**
 * Relay / authority key loading (C Tor `loadkey.c` / `loadkey.h`).
 *
 * Covers `ed_key_init_from_file` flag subset: CREATE, REPLACE, SPLIT,
 * MISSING_SECRET_OK, OMIT_SECRET, EXPLICIT_FNAME.
 *
 * Inventory: `L1:feature/keymgt/loadkey.c`
 */
object LoadKey {
    const val INIT_ED_KEY_CREATE: Int = 1 shl 0
    const val INIT_ED_KEY_REPLACE: Int = 1 shl 1
    const val INIT_ED_KEY_SPLIT: Int = 1 shl 2
    const val INIT_ED_KEY_MISSING_SECRET_OK: Int = 1 shl 3
    const val INIT_ED_KEY_NEEDCERT: Int = 1 shl 4
    const val INIT_ED_KEY_OMIT_SECRET: Int = 1 shl 7
    const val INIT_ED_KEY_EXPLICIT_FNAME: Int = 1 shl 12

    fun loadOrCreateOrCerts(keysDir: Path): OrCertMaterial {
        Files.createDirectories(keysDir)
        return OrCertMaterial.loadOrGenerate(keysDir)
    }

    fun loadOrCreateEd25519Identity(keysDir: Path): Ed25519KeyPair {
        Files.createDirectories(keysDir)
        val base = keysDir.resolve("ed25519_master_id")
        return edKeyInitFromFile(
            base,
            INIT_ED_KEY_CREATE or INIT_ED_KEY_SPLIT,
        ) ?: error("failed to init ed25519 identity")
    }

    /**
     * C Tor `ed_key_init_from_file` (secret/public split files; encrypted path not yet).
     *
     * [fnameBase] is the stem (`…/ed25519_master_id`) unless [INIT_ED_KEY_EXPLICIT_FNAME]
     * is set, in which case it is the secret-key path itself.
     */
    fun edKeyInitFromFile(fnameBase: Path, flags: Int): Ed25519KeyPair? {
        val tryLoad = flags and INIT_ED_KEY_REPLACE == 0
        val create = flags and INIT_ED_KEY_CREATE != 0
        val split = flags and INIT_ED_KEY_SPLIT != 0
        val omitSecret = flags and INIT_ED_KEY_OMIT_SECRET != 0
        val missingSecretOk = flags and INIT_ED_KEY_MISSING_SECRET_OK != 0
        val explicit = flags and INIT_ED_KEY_EXPLICIT_FNAME != 0

        val secretPath: Path
        val publicPath: Path
        if (explicit) {
            secretPath = fnameBase
            publicPath = Path.of(fnameBase.toString() + "_public_key")
        } else {
            secretPath = Path.of(fnameBase.toString() + "_secret_key")
            publicPath = Path.of(fnameBase.toString() + "_public_key")
        }
        val parent = secretPath.parent
        if (parent != null) Files.createDirectories(parent)

        if (tryLoad) {
            val haveSecret = Files.isRegularFile(secretPath) && Files.size(secretPath) == 32L
            val havePublic = Files.isRegularFile(publicPath) && Files.size(publicPath) == 32L
            when {
                haveSecret -> {
                    val sk = Files.readAllBytes(secretPath)
                    val pk = if (havePublic) {
                        Files.readAllBytes(publicPath)
                    } else {
                        publicFromSecret(sk).also { derived ->
                            if (split) Files.write(publicPath, derived)
                        }
                    }
                    return Ed25519KeyPair(sk, pk)
                }
                havePublic && (omitSecret || missingSecretOk) -> {
                    val pk = Files.readAllBytes(publicPath)
                    return Ed25519KeyPair(ByteArray(32), pk)
                }
                havePublic && !create -> return null
            }
        }

        if (!create && flags and INIT_ED_KEY_REPLACE == 0) return null

        val kp = Ed25519Keys.generate()
        if (!omitSecret) {
            Files.write(secretPath, kp.privateKey)
        }
        if (split || !Files.exists(publicPath)) {
            Files.write(publicPath, kp.publicKey)
        }
        return kp
    }

    /** C Tor `ed_key_new` — fresh keypair. */
    fun edKeyNew(): Ed25519KeyPair = Ed25519Keys.generate()

    fun publicFromSecret(secret: ByteArray): ByteArray {
        require(secret.size == 32)
        val pub = ByteArray(Ed25519.PUBLIC_KEY_SIZE)
        Ed25519.generatePublicKey(secret, 0, pub, 0)
        return pub
    }
}
