package org.kotlintor.hs

import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Blind
import org.kotlintor.util.concat
import org.kotlintor.util.u64be

/**
 * v3 onion identity key blinding + subcredentials (rend-spec-v3 KEYBLIND / SUBCRED).
 */
object HsKeyBlind {
    private val BLIND_STRING = "Derive temporary signing key\u0000".toByteArray()
    private val ED25519_BASEPOINT =
        ("(15112221349535400772501151409588531511454012693041857206046113283949847762202, " +
            "46316835694926478169428394003475163141307993866256225615783033603165251855960)")
            .toByteArray()

    fun blindingFactor(
        publicIdentity: ByteArray,
        period: HsTimePeriod,
        secret: ByteArray = ByteArray(0),
    ): ByteArray {
        require(publicIdentity.size == 32)
        return Digests.sha3_256(
            concat(
                BLIND_STRING,
                publicIdentity,
                secret,
                ED25519_BASEPOINT,
                "key-blind".toByteArray(),
                u64be(period.intervalNum),
                u64be(period.lengthMinutes),
            ),
        )
    }

    fun blindPublicKey(
        publicIdentity: ByteArray,
        period: HsTimePeriod,
        secret: ByteArray = ByteArray(0),
    ): ByteArray {
        val h = blindingFactor(publicIdentity, period, secret)
        return Ed25519Blind.blindPublicKey(publicIdentity, h)
    }

    /** Blind the identity secret seed into an expanded KS_hs_blind_id keypair. */
    fun blindSecretKey(
        privateIdentitySeed: ByteArray,
        publicIdentity: ByteArray,
        period: HsTimePeriod,
        secret: ByteArray = ByteArray(0),
    ): Ed25519Blind.ExpandedSecret {
        val expanded = Ed25519Blind.expandSecretKey(privateIdentitySeed)
        check(expanded.publicKey.contentEquals(publicIdentity)) {
            "identity public key does not match seed"
        }
        val h = blindingFactor(publicIdentity, period, secret)
        val blinded = Ed25519Blind.blindKeypair(expanded, h)
        val expectPub = blindPublicKey(publicIdentity, period, secret)
        check(blinded.publicKey.contentEquals(expectPub)) {
            "blinded public mismatch (secret vs public path)"
        }
        return blinded
    }

    fun credential(publicIdentity: ByteArray): ByteArray {
        require(publicIdentity.size == 32)
        return Digests.sha3_256(concat("credential".toByteArray(), publicIdentity))
    }

    fun subcredential(publicIdentity: ByteArray, blindedPublic: ByteArray): ByteArray {
        require(publicIdentity.size == 32 && blindedPublic.size == 32)
        return Digests.sha3_256(
            concat("subcredential".toByteArray(), credential(publicIdentity), blindedPublic),
        )
    }

    /** Index used to place descriptors on the HSDir ring. */
    fun serviceIndex(
        blindedPublic: ByteArray,
        replica: Long,
        period: HsTimePeriod,
    ): ByteArray {
        require(blindedPublic.size == 32)
        require(replica in 1..16)
        return Digests.sha3_256(
            concat(
                "store-at-idx".toByteArray(),
                blindedPublic,
                u64be(replica),
                u64be(period.lengthMinutes),
                u64be(period.intervalNum),
            ),
        )
    }

    fun relayIndex(
        nodeEd25519Identity: ByteArray,
        sharedRandom: ByteArray,
        period: HsTimePeriod,
    ): ByteArray {
        require(nodeEd25519Identity.size == 32)
        require(sharedRandom.size == 32)
        return Digests.sha3_256(
            concat(
                "node-idx".toByteArray(),
                nodeEd25519Identity,
                sharedRandom,
                u64be(period.intervalNum),
                u64be(period.lengthMinutes),
            ),
        )
    }
}
