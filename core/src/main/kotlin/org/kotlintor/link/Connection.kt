package org.kotlintor.link

/**
 * Connection module entry (C Tor `connection.c`).
 *
 * Inventory: `L1:core/mainloop/connection.c`
 *
 * Hierarchy: [Connection] / [ConnectionTable] / typed handles in [ConnectionSt].
 * (Object is not named `Connection` to avoid clashing with the open class.)
 */
object ConnectionModule {
    fun clear() = ConnectionTable.clear()

    fun count(): Int = ConnectionTable.count()

    fun countOpen(): Int = ConnectionTable.countOpen()

    fun get(id: Long): Connection? = ConnectionTable.get(id)

    fun byType(type: ConnectionType): List<Connection> = ConnectionTable.byType(type)

    fun newOr(host: String, port: Int, isClient: Boolean = true): OrConnectionHandle =
        ConnectionTable.newOr(host, port, isClient)

    fun newAp(peerHost: String, port: Int, socksUser: String? = null): EntryConnectionHandle =
        ConnectionTable.newEntry(peerHost, port, socksUser)

    fun remove(id: Long): Connection? = ConnectionTable.remove(id)
}
