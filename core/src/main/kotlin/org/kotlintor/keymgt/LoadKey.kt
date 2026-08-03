package org.kotlintor.keymgt

import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.link.OrCertMaterial
import java.nio.file.Files
import java.nio.file.Path

/**
 * Relay / authority key loading helpers (C Tor `loadkey.c` lite).
 *
 * Inventory: `L1:feature/keymgt/loadkey.c`
 */
object LoadKey {
    fun loadOrCreateOrCerts(keysDir: Path): OrCertMaterial {
        Files.createDirectories(keysDir)
        return OrCertMaterial.loadOrGenerate(keysDir)
    }

    fun loadOrCreateEd25519Identity(keysDir: Path): Ed25519KeyPair {
        Files.createDirectories(keysDir)
        val edPriv = keysDir.resolve("ed25519_master_id_secret_key")
        val edPub = keysDir.resolve("ed25519_master_id_public_key")
        if (Files.exists(edPriv) && Files.size(edPriv) == 32L &&
            Files.exists(edPub) && Files.size(edPub) == 32L
        ) {
            return Ed25519KeyPair(Files.readAllBytes(edPriv), Files.readAllBytes(edPub))
        }
        return Ed25519Keys.generate().also {
            Files.write(edPriv, it.privateKey)
            Files.write(edPub, it.publicKey)
        }
    }
}
