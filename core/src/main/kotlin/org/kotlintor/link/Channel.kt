package org.kotlintor.link

/**
 * Channel abstraction (C Tor `channel.c`).
 *
 * Inventory: `L1:core/or/channel.c`
 * L3 ops: `channel_*` via [OrChannel] / [ChannelTable].
 *
 * Implementation: [OrChannel] / [ChannelTable].
 */
object Channel {
    fun clear() = ChannelTable.clear()

    fun count(): Int = ChannelTable.count()

    fun openCount(): Int = ChannelTable.openCount()

    fun get(gid: Long): OrChannel? = ChannelTable.get(gid)

    fun open(remoteAddr: String, remotePort: Int): OrChannel {
        val ch = OrChannel(remoteAddr = remoteAddr, remotePort = remotePort)
        ch.markOpen()
        return ChannelTable.register(ch)
    }

    fun queueCell(ch: OrChannel, cell: ByteArray): Boolean = ch.queueOut(cell)

    fun close(ch: OrChannel) {
        ch.markClosed()
        ChannelTable.removeByIdentity(ch)
        ChannelTable.remove(ch.globalId)
    }

    // --- C Tor `channel.h` op aliases (L3) ---

    /** C Tor `channel_init`. */
    fun init(remoteAddr: String = "", remotePort: Int = 0): OrChannel =
        ChannelTable.register(OrChannel(remoteAddr = remoteAddr, remotePort = remotePort))

    /** C Tor `channel_connect`. */
    fun connect(remoteAddr: String, remotePort: Int): OrChannel = open(remoteAddr, remotePort)

    /** C Tor `channel_change_state_open`. */
    fun changeStateOpen(ch: OrChannel) = ch.markOpen()

    /** C Tor `channel_change_state`. */
    fun changeState(ch: OrChannel, state: ChannelState) {
        when (state) {
            ChannelState.OPEN -> ch.markOpen()
            ChannelState.CLOSING -> ch.markClosing()
            ChannelState.CLOSED -> ch.markClosed()
            ChannelState.ERROR -> {
                ch.state = ChannelState.ERROR
                ch.clearOutbuf()
                ch.clearInbuf()
            }
            ChannelState.OPENING -> ch.state = ChannelState.OPENING
        }
    }

    /** C Tor `channel_closed` / close from lower layer. */
    fun closed(ch: OrChannel) = close(ch)

    fun closeFromLowerLayer(ch: OrChannel) = close(ch)

    fun closeForError(ch: OrChannel) {
        ch.state = ChannelState.ERROR
        close(ch)
    }

    /** C Tor `channel_find_by_global_id`. */
    fun findByGlobalId(gid: Long): OrChannel? = get(gid)

    /** C Tor `channel_free_all`. */
    fun freeAll() = clear()

    /** C Tor `channel_free_`. */
    fun free(ch: OrChannel) = close(ch)

    /** C Tor `channel_has_queued_writes`. */
    fun hasQueuedWrites(ch: OrChannel): Boolean = ch.outbufBytes > 0 || ch.cellsQueued > 0

    /** C Tor `channel_is_better` — prefer open + fewer queued cells. */
    fun isBetter(a: OrChannel, b: OrChannel): Boolean {
        if (a.state == ChannelState.OPEN && b.state != ChannelState.OPEN) return true
        if (a.state != ChannelState.OPEN && b.state == ChannelState.OPEN) return false
        return a.cellsQueued < b.cellsQueued
    }

    /** C Tor `channel_is_bad_for_new_circs`. */
    fun isBadForNewCircs(ch: OrChannel): Boolean =
        ch.state != ChannelState.OPEN || ch.outbufBytes > OrChannel.MAX_OUTBUF / 2

    /** C Tor `channel_add_to_digest_map` / clear identity. */
    fun addToDigestMap(ch: OrChannel, identityHex: String) {
        ch.identityDigestHex = identityHex.uppercase()
        ChannelTable.putIdentity(ch)
    }

    fun clearIdentityDigest(ch: OrChannel) {
        ChannelTable.removeByIdentity(ch)
        ch.identityDigestHex = null
    }

    fun findByRemoteIdentity(identityHex: String): OrChannel? =
        ChannelTable.getByIdentity(identityHex)

    fun clearRemoteEnd(ch: OrChannel) {
        ch.remoteAddr = ""
        ch.remotePort = 0
    }

    fun clearClient(ch: OrChannel) {
        ch.isClient = false
    }

    fun checkForDuplicates(identityHex: String): Boolean =
        ChannelTable.getByIdentity(identityHex) != null

    fun describeTransport(ch: OrChannel): String =
        "or ${ch.remoteAddr}:${ch.remotePort} gid=${ch.globalId} state=${ch.state}"

    fun dumpstats(ch: OrChannel): String =
        "gid=${ch.globalId} out=${ch.outbufBytes} in=${ch.inbufBytes} q=${ch.cellsQueued}"

    fun dumpTransportStatistics(ch: OrChannel): String = dumpstats(ch)

    fun doOpenActions(ch: OrChannel) = changeStateOpen(ch)

    fun getCellHandler(ch: OrChannel): ((ByteArray) -> Unit)? = ch.cellHandler

    /** C Tor `channel_init_listener`. */
    fun initListener(bindAddr: String = "0.0.0.0", bindPort: Int = 0): OrChannel {
        val ch = init(bindAddr, bindPort)
        ch.isClient = false
        changeStateOpen(ch)
        return ch
    }
}
