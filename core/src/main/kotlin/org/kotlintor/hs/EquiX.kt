package org.kotlintor.hs

import org.kotlintor.pow.EquiX as PowEquiX
import org.kotlintor.pow.EquiXSolution

/**
 * Prop327 Equi-X PoW facade over the pure-Kotlin HashX/Equi-X port
 * ([org.kotlintor.pow.EquiX]). Do not use [HsPow] hashcash here.
 */
object EquiX {
    const val ALGORITHM = "equix"

    fun isEquiXAvailable(): Boolean = true

    /** Solve Equi-X for [challenge]; returns 16-byte packed indices or null. */
    fun solveEquix(challenge: ByteArray): ByteArray? =
        PowEquiX.solve(challenge).firstOrNull()?.toBytes()

    fun verifyEquixBytes(challenge: ByteArray, solution: ByteArray): Boolean =
        PowEquiX.verifyOk(challenge, EquiXSolution.fromBytes(solution))

    /**
     * Full prop327 solve (Equi-X + Blake2b effort) — prefer this over hashcash [HsPow].
     */
    fun solveProp327(
        blindedId: ByteArray,
        seed: ByteArray,
        effort: Int,
        maxAttempts: Long = 50_000L,
    ): HsPowProp327.Solution? =
        HsPowProp327.solve(blindedId, seed, effort, maxAttempts)

    fun verifyProp327(sol: HsPowProp327.Solution, blindedId: ByteArray, minEffort: Int = 1): Boolean =
        HsPowProp327.verifySolution(sol, blindedId, minEffort)
}
