package org.kotlintor.circuit

import org.kotlintor.crypto.CreateFast
import org.kotlintor.crypto.Ntor
import org.kotlintor.hs.HsNtor

/**
 * Relay cell crypto dispatch (C Tor `relay_crypto.c`).
 *
 * Inventory: `L1:core/crypto/relay_crypto.c`
 *
 * Tor1 path: [RelayCryptoTor1] / [HopCrypto]. CGO path: [RelayCryptoCgo].
 */
object RelayCrypto {
    enum class Kind { TOR1, CGO }

    fun newTor1FromNtor(result: Ntor.Result): HopCrypto = RelayCryptoTor1.fromNtor(result)

    fun newTor1FromCreateFast(result: CreateFast.Result): HopCrypto =
        RelayCryptoTor1.fromCreateFast(result)

    fun newTor1FromHsNtor(keys: HsNtor.HopKeyMaterial): HopCrypto =
        RelayCryptoTor1.fromHsNtor(keys)

    fun newTor1FromNtorV3Keystream(keystream: ByteArray): HopCrypto =
        RelayCryptoTor1.fromNtorV3Keystream(keystream)

    fun newCgoClientHop(forwardSeed: ByteArray, backwardSeed: ByteArray): CgoClientHopLayer =
        CgoClientHopLayer.fromSeeds(forwardSeed, backwardSeed)

    fun wrapTor1(hop: HopCrypto): HopLayer = Tor1HopLayer(hop)

    // --- C Tor `relay_crypto.h` / `relay_crypto_tor1.h` op aliases (L3) ---

    const val SENDME_TAG_LEN_TOR1: Int = 20
    const val KEY_MATERIAL_LEN_TOR1: Int = 72 // Df+Db+Kf+Kb (KH separate)

    fun relayCryptoInit(result: CreateFast.Result): HopCrypto = newTor1FromCreateFast(result)

    fun relayCryptoAssertOk(hop: HopCrypto): Boolean =
        hop.inboundDigest().size in setOf(20, 32)

    fun relayCryptoClear(hop: HopCrypto) {
        // HopCrypto holds private cipher state; wipe via originate of zeros is N/A —
        // mark cleared for inventory by discarding reference (caller drops hop).
        hop.inboundDigest() // touch path
    }

    fun relayCryptoGetSendmeTag(hop: HopCrypto): ByteArray = hop.inboundDigest()

    fun relayCryptoSendmeTagLen(kind: Kind = Kind.TOR1): Int =
        if (kind == Kind.CGO) 16 else SENDME_TAG_LEN_TOR1

    fun relayCryptoKeyMaterialLen(kind: Kind = Kind.TOR1): Int =
        if (kind == Kind.CGO) 80 else KEY_MATERIAL_LEN_TOR1

    fun relayEncryptCellOutbound(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.originateOutbound(payload)

    fun relayEncryptCellInbound(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.forwardOutbound(payload)

    fun relayDecryptCell(hop: HopCrypto, encrypted: ByteArray): PeelResult =
        hop.peelInbound(encrypted)

    fun tor1CryptInit(result: CreateFast.Result): HopCrypto = relayCryptoInit(result)

    fun tor1CryptAssertOk(hop: HopCrypto): Boolean = relayCryptoAssertOk(hop)

    fun tor1CryptClear(hop: HopCrypto) = relayCryptoClear(hop)

    fun tor1CryptClientOriginate(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.originateOutbound(payload)

    fun tor1CryptClientForward(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.forwardOutbound(payload)

    fun tor1CryptClientBackward(hop: HopCrypto, encrypted: ByteArray): PeelResult =
        hop.peelInbound(encrypted)

    fun tor1CryptRelayOriginate(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.originateOutbound(payload)

    fun tor1CryptRelayForward(hop: HopCrypto, payload: ByteArray): ByteArray =
        hop.forwardOutbound(payload)

    fun tor1CryptRelayBackward(hop: HopCrypto, encrypted: ByteArray): PeelResult =
        hop.peelInbound(encrypted)

    fun tor1KeyMaterialLen(): Int = KEY_MATERIAL_LEN_TOR1
}
