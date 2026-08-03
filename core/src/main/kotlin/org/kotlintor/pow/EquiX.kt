package org.kotlintor.pow

/**
 * Equi-X solver heap + solve/verify (tevador equix solver.c + equix.c).
 *
 * HASHX_SIZE=8; indices are uint16; solution is 8×uint16 LE packed (16 bytes).
 */
class EquiXSolution(val idx: ShortArray = ShortArray(NUM_IDX)) {
    /** Pack as 8×uint16 little-endian (native Equi-X / Tor wire layout). */
    fun toBytes(): ByteArray {
        val out = ByteArray(NUM_IDX * 2)
        for (i in 0 until NUM_IDX) {
            val v = idx[i].toInt() and 0xffff
            out[i * 2] = v.toByte()
            out[i * 2 + 1] = (v ushr 8).toByte()
        }
        return out
    }

    /** Hex dump of indices as `%04x` each (matches tevador bench printf). */
    fun toIndexHex(): String =
        idx.joinToString("") { "%04x".format(it.toInt() and 0xffff) }

    companion object {
        const val NUM_IDX = 8

        fun fromBytes(bytes: ByteArray): EquiXSolution {
            require(bytes.size == NUM_IDX * 2)
            val s = EquiXSolution()
            for (i in 0 until NUM_IDX) {
                s.idx[i] = ((bytes[i * 2].toInt() and 0xff) or ((bytes[i * 2 + 1].toInt() and 0xff) shl 8)).toShort()
            }
            return s
        }

        /** Parse concatenated `%04x` index dump (not LE memory image). */
        fun fromIndexHex(hex: String): EquiXSolution {
            require(hex.length == NUM_IDX * 4)
            val s = EquiXSolution()
            for (i in 0 until NUM_IDX) {
                s.idx[i] = hex.substring(i * 4, i * 4 + 4).toInt(16).toShort()
            }
            return s
        }
    }
}

enum class EquiXResult {
    OK, CHALLENGE, ORDER, PARTIAL_SUM, FINAL_SUM
}

internal class SolverHeap {
    companion object {
        const val INDEX_SPACE = 1 shl 16
        const val NUM_COARSE_BUCKETS = 256
        const val NUM_FINE_BUCKETS = 128
        const val COARSE_BUCKET_ITEMS = 336
        const val FINE_BUCKET_ITEMS = 12
    }

    val stage1Counts = IntArray(NUM_COARSE_BUCKETS)
    val stage1Idx = ShortArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)
    val stage1Data = LongArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)

    val stage2Counts = IntArray(NUM_COARSE_BUCKETS)
    val stage2Idx = IntArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)
    val stage2Data = LongArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)

    val stage3Counts = IntArray(NUM_COARSE_BUCKETS)
    val stage3Idx = IntArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)
    val stage3Data = IntArray(NUM_COARSE_BUCKETS * COARSE_BUCKET_ITEMS)

    val scratchCounts = IntArray(NUM_FINE_BUCKETS)
    val scratch = ShortArray(NUM_FINE_BUCKETS * FINE_BUCKET_ITEMS)

    fun s1Idx(buck: Int, pos: Int) = stage1Idx[buck * COARSE_BUCKET_ITEMS + pos]
    fun s1Data(buck: Int, pos: Int) = stage1Data[buck * COARSE_BUCKET_ITEMS + pos]
    fun setS1(buck: Int, pos: Int, idx: Int, data: Long) {
        stage1Idx[buck * COARSE_BUCKET_ITEMS + pos] = idx.toShort()
        stage1Data[buck * COARSE_BUCKET_ITEMS + pos] = data
    }

    fun s2Idx(buck: Int, pos: Int) = stage2Idx[buck * COARSE_BUCKET_ITEMS + pos]
    fun s2Data(buck: Int, pos: Int) = stage2Data[buck * COARSE_BUCKET_ITEMS + pos]
    fun setS2(buck: Int, pos: Int, idx: Int, data: Long) {
        stage2Idx[buck * COARSE_BUCKET_ITEMS + pos] = idx
        stage2Data[buck * COARSE_BUCKET_ITEMS + pos] = data
    }

    fun s3Idx(buck: Int, pos: Int) = stage3Idx[buck * COARSE_BUCKET_ITEMS + pos]
    fun s3Data(buck: Int, pos: Int) = stage3Data[buck * COARSE_BUCKET_ITEMS + pos]
    fun setS3(buck: Int, pos: Int, idx: Int, data: Int) {
        stage3Idx[buck * COARSE_BUCKET_ITEMS + pos] = idx
        stage3Data[buck * COARSE_BUCKET_ITEMS + pos] = data
    }
}

object EquiX {
    const val MAX_SOLS = 8
    const val STAGE1_MASK = (1L shl 15) - 1
    const val STAGE2_MASK = (1L shl 30) - 1
    const val FULL_MASK = (1L shl 60) - 1

    private const val NUM_COARSE = SolverHeap.NUM_COARSE_BUCKETS
    private const val NUM_FINE = SolverHeap.NUM_FINE_BUCKETS
    private const val COARSE_ITEMS = SolverHeap.COARSE_BUCKET_ITEMS
    private const val FINE_ITEMS = SolverHeap.FINE_BUCKET_ITEMS
    private const val BUCK_START = 0
    private const val BUCK_END = NUM_COARSE / 2 + 1

    private fun makeItem(bucket: Int, left: Int, right: Int): Int =
        (left shl 17) or (right shl 8) or bucket

    private fun itemBucket(item: Int): Int = Integer.remainderUnsigned(item, NUM_COARSE)
    private fun itemLeftIdx(item: Int): Int = item ushr 17
    private fun itemRightIdx(item: Int): Int = (item ushr 8) and 511
    private fun invertBucket(idx: Int): Int = Integer.remainderUnsigned(-idx, NUM_COARSE)
    private fun invertScratch(idx: Int): Int = Integer.remainderUnsigned(-idx, NUM_FINE)

    private fun treeCmp1(left: Short, right: Short): Boolean =
        (left.toInt() and 0xffff) <= (right.toInt() and 0xffff)

    private fun treeCmp2(a: ShortArray, ao: Int, b: ShortArray, bo: Int): Boolean {
        val la = (a[ao].toInt() and 0xffff) or ((a[ao + 1].toInt() and 0xffff) shl 16)
        val lb = (b[bo].toInt() and 0xffff) or ((b[bo + 1].toInt() and 0xffff) shl 16)
        return Integer.compareUnsigned(la, lb) <= 0
    }

    private fun treeCmp4(a: ShortArray, ao: Int, b: ShortArray, bo: Int): Boolean {
        var la = 0L
        var lb = 0L
        for (i in 0 until 4) {
            la = la or (((a[ao + i].toInt() and 0xffff).toLong()) shl (16 * i))
            lb = lb or (((b[bo + i].toInt() and 0xffff).toLong()) shl (16 * i))
        }
        return java.lang.Long.compareUnsigned(la, lb) <= 0
    }

    private fun swapIdx(arr: ShortArray, i: Int, j: Int) {
        val t = arr[i]; arr[i] = arr[j]; arr[j] = t
    }

    private fun buildSolutionStage1(output: ShortArray, outOff: Int, heap: SolverHeap, root: Int) {
        val bucket = itemBucket(root)
        val bucketInv = invertBucket(bucket)
        val leftParentIdx = itemLeftIdx(root)
        val rightParentIdx = itemRightIdx(root)
        output[outOff] = heap.s1Idx(bucket, leftParentIdx)
        output[outOff + 1] = heap.s1Idx(bucketInv, rightParentIdx)
        if (!treeCmp1(output[outOff], output[outOff + 1])) {
            swapIdx(output, outOff, outOff + 1)
        }
    }

    private fun buildSolutionStage2(output: ShortArray, outOff: Int, heap: SolverHeap, root: Int) {
        val bucket = itemBucket(root)
        val bucketInv = invertBucket(bucket)
        val leftParent = heap.s2Idx(bucket, itemLeftIdx(root))
        val rightParent = heap.s2Idx(bucketInv, itemRightIdx(root))
        buildSolutionStage1(output, outOff, heap, leftParent)
        buildSolutionStage1(output, outOff + 2, heap, rightParent)
        if (!treeCmp2(output, outOff, output, outOff + 2)) {
            swapIdx(output, outOff, outOff + 2)
            swapIdx(output, outOff + 1, outOff + 3)
        }
    }

    private fun buildSolution(sol: EquiXSolution, heap: SolverHeap, left: Int, right: Int) {
        buildSolutionStage2(sol.idx, 0, heap, left)
        buildSolutionStage2(sol.idx, 4, heap, right)
        if (!treeCmp4(sol.idx, 0, sol.idx, 4)) {
            swapIdx(sol.idx, 0, 4); swapIdx(sol.idx, 1, 5)
            swapIdx(sol.idx, 2, 6); swapIdx(sol.idx, 3, 7)
        }
    }

    private fun solveStage0(hashFunc: HashX, heap: SolverHeap) {
        heap.stage1Counts.fill(0)
        for (i in 0 until SolverHeap.INDEX_SPACE) {
            val value = hashFunc.execValue(i.toLong())
            val bucketIdx = java.lang.Long.remainderUnsigned(value, NUM_COARSE.toLong()).toInt()
            val itemIdx = heap.stage1Counts[bucketIdx]
            if (itemIdx >= COARSE_ITEMS) continue
            heap.stage1Counts[bucketIdx] = itemIdx + 1
            heap.setS1(bucketIdx, itemIdx, i, java.lang.Long.divideUnsigned(value, NUM_COARSE.toLong()))
        }
    }

    private fun solveStage1(heap: SolverHeap) {
        heap.stage2Counts.fill(0)
        for (bucketIdx in BUCK_START until BUCK_END) {
            val cplBucket = invertBucket(bucketIdx)
            heap.scratchCounts.fill(0)
            val cplBuckSize = heap.stage1Counts[cplBucket]
            for (itemIdx in 0 until cplBuckSize) {
                val value = heap.s1Data(cplBucket, itemIdx)
                val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
                val fineItemIdx = heap.scratchCounts[fineBuckIdx]
                if (fineItemIdx >= FINE_ITEMS) continue
                heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1
                heap.scratch[fineBuckIdx * FINE_ITEMS + fineItemIdx] = itemIdx.toShort()
                if (cplBucket == bucketIdx) makePairs1(heap, bucketIdx, cplBucket, itemIdx)
            }
            if (cplBucket != bucketIdx) {
                val buckSize = heap.stage1Counts[bucketIdx]
                for (itemIdx in 0 until buckSize) {
                    makePairs1(heap, bucketIdx, cplBucket, itemIdx)
                }
            }
        }
    }

    private fun makePairs1(heap: SolverHeap, bucketIdx: Int, cplBucket: Int, itemIdx: Int) {
        val carry = if (bucketIdx != 0) 1L else 0L
        val value = heap.s1Data(bucketIdx, itemIdx) + carry
        val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
        val fineCplBucket = invertScratch(fineBuckIdx)
        val fineCplSize = heap.scratchCounts[fineCplBucket]
        for (fineIdx in 0 until fineCplSize) {
            val cplIndex = heap.scratch[fineCplBucket * FINE_ITEMS + fineIdx].toInt() and 0xffff
            val cplValue = heap.s1Data(cplBucket, cplIndex)
            var sum = value + cplValue
            sum = java.lang.Long.divideUnsigned(sum, NUM_FINE.toLong())
            val s2BuckId = java.lang.Long.remainderUnsigned(sum, NUM_COARSE.toLong()).toInt()
            val s2ItemId = heap.stage2Counts[s2BuckId]
            if (s2ItemId >= COARSE_ITEMS) continue
            heap.stage2Counts[s2BuckId] = s2ItemId + 1
            heap.setS2(
                s2BuckId, s2ItemId,
                makeItem(bucketIdx, itemIdx, cplIndex),
                java.lang.Long.divideUnsigned(sum, NUM_COARSE.toLong()),
            )
        }
    }

    private fun solveStage2(heap: SolverHeap) {
        heap.stage3Counts.fill(0)
        for (bucketIdx in BUCK_START until BUCK_END) {
            val cplBucket = invertBucket(bucketIdx)
            heap.scratchCounts.fill(0)
            val cplBuckSize = heap.stage2Counts[cplBucket]
            for (itemIdx in 0 until cplBuckSize) {
                val value = heap.s2Data(cplBucket, itemIdx)
                val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
                val fineItemIdx = heap.scratchCounts[fineBuckIdx]
                if (fineItemIdx >= FINE_ITEMS) continue
                heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1
                heap.scratch[fineBuckIdx * FINE_ITEMS + fineItemIdx] = itemIdx.toShort()
                if (cplBucket == bucketIdx) makePairs2(heap, bucketIdx, cplBucket, itemIdx)
            }
            if (cplBucket != bucketIdx) {
                val buckSize = heap.stage2Counts[bucketIdx]
                for (itemIdx in 0 until buckSize) {
                    makePairs2(heap, bucketIdx, cplBucket, itemIdx)
                }
            }
        }
    }

    private fun makePairs2(heap: SolverHeap, bucketIdx: Int, cplBucket: Int, itemIdx: Int) {
        val carry = if (bucketIdx != 0) 1L else 0L
        val value = heap.s2Data(bucketIdx, itemIdx) + carry
        val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
        val fineCplBucket = invertScratch(fineBuckIdx)
        val fineCplSize = heap.scratchCounts[fineCplBucket]
        for (fineIdx in 0 until fineCplSize) {
            val cplIndex = heap.scratch[fineCplBucket * FINE_ITEMS + fineIdx].toInt() and 0xffff
            val cplValue = heap.s2Data(cplBucket, cplIndex)
            var sum = value + cplValue
            sum = java.lang.Long.divideUnsigned(sum, NUM_FINE.toLong())
            val s3BuckId = java.lang.Long.remainderUnsigned(sum, NUM_COARSE.toLong()).toInt()
            val s3ItemId = heap.stage3Counts[s3BuckId]
            if (s3ItemId >= COARSE_ITEMS) continue
            heap.stage3Counts[s3BuckId] = s3ItemId + 1
            heap.setS3(
                s3BuckId, s3ItemId,
                makeItem(bucketIdx, itemIdx, cplIndex),
                java.lang.Long.divideUnsigned(sum, NUM_COARSE.toLong()).toInt(),
            )
        }
    }

    private fun solveStage3(heap: SolverHeap, output: Array<EquiXSolution>): Int {
        var solsFound = 0
        for (bucketIdx in BUCK_START until BUCK_END) {
            val cplBucket = (-bucketIdx) and (NUM_COARSE - 1)
            heap.scratchCounts.fill(0)
            val cplBuckSize = heap.stage3Counts[cplBucket]
            for (itemIdx in 0 until cplBuckSize) {
                val value = heap.s3Data(cplBucket, itemIdx).toLong() and 0xffff_ffffL
                val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
                val fineItemIdx = heap.scratchCounts[fineBuckIdx]
                if (fineItemIdx >= FINE_ITEMS) continue
                heap.scratchCounts[fineBuckIdx] = fineItemIdx + 1
                heap.scratch[fineBuckIdx * FINE_ITEMS + fineItemIdx] = itemIdx.toShort()
                if (cplBucket == bucketIdx) {
                    solsFound = makePairs3(heap, bucketIdx, cplBucket, itemIdx, output, solsFound)
                    if (solsFound >= MAX_SOLS) return solsFound
                }
            }
            if (cplBucket != bucketIdx) {
                val buckSize = heap.stage3Counts[bucketIdx]
                for (itemIdx in 0 until buckSize) {
                    solsFound = makePairs3(heap, bucketIdx, cplBucket, itemIdx, output, solsFound)
                    if (solsFound >= MAX_SOLS) return solsFound
                }
            }
        }
        return solsFound
    }

    private fun makePairs3(
        heap: SolverHeap,
        bucketIdx: Int,
        cplBucket: Int,
        itemIdx: Int,
        output: Array<EquiXSolution>,
        solsFoundIn: Int,
    ): Int {
        var solsFound = solsFoundIn
        val carry = if (bucketIdx != 0) 1 else 0
        val value = (heap.s3Data(bucketIdx, itemIdx) + carry).toLong() and 0xffff_ffffL
        val fineBuckIdx = java.lang.Long.remainderUnsigned(value, NUM_FINE.toLong()).toInt()
        val fineCplBucket = invertScratch(fineBuckIdx)
        val fineCplSize = heap.scratchCounts[fineCplBucket]
        for (fineIdx in 0 until fineCplSize) {
            val cplIndex = heap.scratch[fineCplBucket * FINE_ITEMS + fineIdx].toInt() and 0xffff
            val cplValue = heap.s3Data(cplBucket, cplIndex).toLong() and 0xffff_ffffL
            var sum = value + cplValue
            sum = java.lang.Long.divideUnsigned(sum, NUM_FINE.toLong())
            if ((sum and STAGE1_MASK) == 0L) {
                val itemLeft = heap.s3Idx(bucketIdx, itemIdx)
                val itemRight = heap.s3Idx(cplBucket, cplIndex)
                if (output[solsFound] == null) {
                    // shouldn't happen
                }
                buildSolution(output[solsFound], heap, itemLeft, itemRight)
                solsFound++
                if (solsFound >= MAX_SOLS) return solsFound
            }
        }
        return solsFound
    }

    private val threadHeap = ThreadLocal.withInitial { SolverHeap() }
    private val threadHash = ThreadLocal.withInitial { HashX() }

    fun solve(challenge: ByteArray): List<EquiXSolution> {
        val hashFunc = threadHash.get()
        if (!hashFunc.make(challenge)) return emptyList()
        val heap = threadHeap.get()
        val output = Array(MAX_SOLS) { EquiXSolution() }
        solveStage0(hashFunc, heap)
        solveStage1(heap)
        solveStage2(heap)
        val n = solveStage3(heap, output)
        return (0 until n).map { output[it] }
    }

    private fun verifyOrder(solution: EquiXSolution): Boolean {
        val idx = solution.idx
        return treeCmp4(idx, 0, idx, 4) &&
            treeCmp2(idx, 0, idx, 2) &&
            treeCmp2(idx, 4, idx, 6) &&
            treeCmp1(idx[0], idx[1]) &&
            treeCmp1(idx[2], idx[3]) &&
            treeCmp1(idx[4], idx[5]) &&
            treeCmp1(idx[6], idx[7])
    }

    private fun sumPair(hashFunc: HashX, left: Int, right: Int): Long =
        hashFunc.execValue(left.toLong() and 0xffffL) + hashFunc.execValue(right.toLong() and 0xffffL)

    private fun verifyInternal(hashFunc: HashX, solution: EquiXSolution): EquiXResult {
        val idx = solution.idx
        fun u(i: Int) = idx[i].toInt() and 0xffff
        val pair0 = sumPair(hashFunc, u(0), u(1))
        if ((pair0 and STAGE1_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair1 = sumPair(hashFunc, u(2), u(3))
        if ((pair1 and STAGE1_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair4 = pair0 + pair1
        if ((pair4 and STAGE2_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair2 = sumPair(hashFunc, u(4), u(5))
        if ((pair2 and STAGE1_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair3 = sumPair(hashFunc, u(6), u(7))
        if ((pair3 and STAGE1_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair5 = pair2 + pair3
        if ((pair5 and STAGE2_MASK) != 0L) return EquiXResult.PARTIAL_SUM
        val pair6 = pair4 + pair5
        if ((pair6 and FULL_MASK) != 0L) return EquiXResult.FINAL_SUM
        return EquiXResult.OK
    }

    fun verify(challenge: ByteArray, solution: EquiXSolution): EquiXResult {
        if (!verifyOrder(solution)) return EquiXResult.ORDER
        val hashFunc = threadHash.get()
        if (!hashFunc.make(challenge)) return EquiXResult.CHALLENGE
        return verifyInternal(hashFunc, solution)
    }

    fun verifyOk(challenge: ByteArray, solution: EquiXSolution): Boolean =
        verify(challenge, solution) == EquiXResult.OK
}

/** JVM-facing facade used by [org.kotlintor.hs.EquiX] reflection / direct calls. */
object EquiXEngine {
    @JvmStatic
    fun solveFirst(challenge: ByteArray): ByteArray? =
        EquiX.solve(challenge).firstOrNull()?.toBytes()

    @JvmStatic
    fun verify(challenge: ByteArray, solution: ByteArray): Boolean =
        EquiX.verifyOk(challenge, EquiXSolution.fromBytes(solution))

    @JvmStatic
    fun solveAll(challenge: ByteArray): Array<ByteArray> =
        EquiX.solve(challenge).map { it.toBytes() }.toTypedArray()
}
