package org.kotlintor.crypto

/**
 * Prop359 Counter Galois Onion hop layers (Arti `cgo.rs` CryptState + client/relay).
 *
 * Seed per direction: UIV keys (64) ‖ nonce (16) = 80 bytes.
 * Client layers always use UIV.decrypt; relay layers always use UIV.encrypt.
 */
class CgoHop(
    keys: ByteArray,
    nonce: ByteArray,
    tag: ByteArray = ByteArray(Cgo.TAG_LEN),
) {
    init {
        require(keys.size == Cgo.KLEN_UIV)
        require(nonce.size == Cgo.BLK_LEN && tag.size == Cgo.BLK_LEN)
    }

    var keys: ByteArray = keys.copyOf()
        private set
    var nonce: ByteArray = nonce.copyOf()
        private set
    var tag: ByteArray = tag.copyOf()
        private set

    fun snapshot(): Triple<ByteArray, ByteArray, ByteArray> =
        Triple(keys.copyOf(), nonce.copyOf(), tag.copyOf())

    private fun updateFromNonce(n: ByteArray) {
        val (newKeys, newNonce) = Cgo.Uiv.update(keys, n)
        keys = newKeys
        nonce = newNonce
    }

    private fun h(cmd: Int): ByteArray = tag + byteArrayOf(cmd.toByte())

    // --- Client outbound (toward network) ---

    /** Place nonce as tag, encrypt through this hop, then UPDATE keys. Returns sendme tag (ciphertext tag). */
    fun clientOriginate(cmd: Int, cell: ByteArray): ByteArray {
        require(cell.size == Cgo.CELL_DATA_LEN)
        nonce.copyInto(cell, 0, 0, Cgo.TAG_LEN)
        clientEncryptOutbound(cmd, cell)
        updateFromNonce(nonce)
        return cell.copyOfRange(0, Cgo.TAG_LEN)
    }

    fun clientEncryptOutbound(cmd: Int, cell: ByteArray) {
        require(cell.size == Cgo.CELL_DATA_LEN)
        val tNew = cell.copyOfRange(0, Cgo.TAG_LEN)
        val out = Cgo.Uiv.decrypt(keys, h(cmd), cell)
        out.copyInto(cell)
        tag = tNew
    }

    // --- Client inbound (from network) ---

    /** Decrypt one hop. Returns sendme tag if this hop originated the cell, else null. */
    fun clientDecryptInbound(cmd: Int, cell: ByteArray): ByteArray? {
        require(cell.size == Cgo.CELL_DATA_LEN)
        val tOrig = cell.copyOfRange(0, Cgo.TAG_LEN)
        val out = Cgo.Uiv.decrypt(keys, h(cmd), cell)
        out.copyInto(cell)
        tag = tOrig
        return if (cell.copyOfRange(0, Cgo.TAG_LEN).contentEquals(nonce)) {
            updateFromNonce(tOrig)
            // After UPDATE, Arti sets nonce = updated material from t_orig stream;
            // updateFromNonce already replaced nonce. Tag stays tOrig (pre-update input).
            tag.copyOf()
        } else {
            null
        }
    }

    // --- Relay outbound (away from client = decrypting client→exit) ---

    fun relayDecryptOutbound(cmd: Int, cell: ByteArray): ByteArray? {
        require(cell.size == Cgo.CELL_DATA_LEN)
        val sendme = cell.copyOfRange(0, Cgo.TAG_LEN)
        val out = Cgo.Uiv.encrypt(keys, h(cmd), cell)
        out.copyInto(cell)
        tag = cell.copyOfRange(0, Cgo.TAG_LEN)
        return if (tag.contentEquals(nonce)) {
            updateFromNonce(nonce)
            sendme
        } else {
            null
        }
    }

    // --- Relay inbound (toward client) ---

    fun relayOriginate(cmd: Int, cell: ByteArray): ByteArray {
        require(cell.size == Cgo.CELL_DATA_LEN)
        nonce.copyInto(cell, 0, 0, Cgo.TAG_LEN)
        relayEncryptInbound(cmd, cell)
        nonce = cell.copyOfRange(0, Cgo.TAG_LEN)
        updateFromNonce(nonce)
        return tag.copyOf()
    }

    fun relayEncryptInbound(cmd: Int, cell: ByteArray) {
        require(cell.size == Cgo.CELL_DATA_LEN)
        val out = Cgo.Uiv.encrypt(keys, h(cmd), cell)
        out.copyInto(cell)
        tag = cell.copyOfRange(0, Cgo.TAG_LEN)
    }

    companion object {
        const val SEED_LEN = Cgo.KLEN_UIV + Cgo.BLK_LEN // 80

        fun fromSeed(seed: ByteArray, tag: ByteArray = ByteArray(Cgo.TAG_LEN)): CgoHop {
            require(seed.size == SEED_LEN)
            return CgoHop(
                keys = seed.copyOfRange(0, Cgo.KLEN_UIV),
                nonce = seed.copyOfRange(Cgo.KLEN_UIV, SEED_LEN),
                tag = tag,
            )
        }
    }
}
