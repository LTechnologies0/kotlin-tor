package org.kotlintor.hs

import org.kotlintor.pow.EquiX as PowEquiX
import org.kotlintor.pow.EquiXSolution

/**
 * Prop327 Equi-X PoW facade over the pure-Kotlin HashX/Equi-X port.
 */
object EquiX {
    const val ALGORITHM = "equix"

    fun solve(seed: ByteArray, effort: Int, maxAttempts: Long = 2_000_000L): HsPow.Solution? =
        HsPow.solve(HsPow.Challenge(seed, effort), maxAttempts)

    fun verify(solution: HsPow.Solution): Boolean = HsPow.verify(solution)

    fun isEquiXAvailable(): Boolean = true

    /** Solve Equi-X for [challenge]; returns 16-byte packed indices or null. */
    fun solveEquix(challenge: ByteArray): ByteArray? =
        PowEquiX.solve(challenge).firstOrNull()?.toBytes()

    fun verifyEquixBytes(challenge: ByteArray, solution: ByteArray): Boolean =
        PowEquiX.verifyOk(challenge, EquiXSolution.fromBytes(solution))
}
