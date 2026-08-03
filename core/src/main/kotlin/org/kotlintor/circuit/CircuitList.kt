package org.kotlintor.circuit

import java.util.concurrent.ConcurrentHashMap

/**
 * Global circuit table (C Tor `circuitlist.c` lite).
 *
 * Tracks [CircuitMeta] for origin and OR circuits without forking the crypto
 * engine. Hot paths register/unregister as circuits open/close.
 */
object CircuitList {
    private val byId = ConcurrentHashMap<Long, CircuitMeta>()

    fun put(meta: CircuitMeta) {
        byId[meta.kind.circId] = meta
    }

    fun get(circId: Long): CircuitMeta? = byId[circId]

    fun remove(circId: Long): CircuitMeta? = byId.remove(circId)

    fun all(): Collection<CircuitMeta> = byId.values

    fun origins(): List<CircuitMeta> = byId.values.filter { it.isOrigin }

    fun ors(): List<CircuitMeta> = byId.values.filter { it.isOr }

    fun count(): Int = byId.size

    fun clear() = byId.clear()

    fun byPurpose(purpose: org.kotlintor.cell.CircuitPurpose): List<CircuitMeta> =
        byId.values.filter { it.purpose == purpose }

    fun markDirty(circId: Long) {
        byId[circId]?.dirty = true
    }

    fun dirtyCircuits(): List<CircuitMeta> = byId.values.filter { it.dirty }

    fun countOrigins(): Int = origins().size

    fun countOrs(): Int = ors().size

    fun registerOrigin(
        circId: Long,
        purpose: org.kotlintor.cell.CircuitPurpose = org.kotlintor.cell.CircuitPurpose.GENERAL,
        pathLength: Int = 3,
    ): CircuitMeta {
        val meta = CircuitMeta(CircuitKind.Origin(circId, purpose, pathLength))
        put(meta)
        return meta
    }

    fun registerOr(
        circId: Long,
        isExit: Boolean = false,
        isDir: Boolean = false,
    ): CircuitMeta {
        val meta = CircuitMeta(CircuitKind.Or(circId, isExit = isExit, isDir = isDir, cryptoEstablished = true))
        put(meta)
        return meta
    }
}
