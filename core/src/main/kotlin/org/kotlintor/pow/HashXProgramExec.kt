package org.kotlintor.pow

/**
 * HashX interpreted register machine (tevador program_exec.c).
 */
object HashXProgramExec {
    /** Unsigned 64×64 → high 64 (portable; Kotlin ULong mul truncates). */
    private fun umulh(a: Long, b: Long): Long {
        val aL = a.toULong(); val bL = b.toULong()
        val al = aL and 0xffffffffu; val ah = aL shr 32
        val bl = bL and 0xffffffffu; val bh = bL shr 32
        val x00 = al * bl
        val x01 = al * bh
        val x10 = ah * bl
        val x11 = ah * bh
        val m1 = (x10 and 0xffffffffu) + (x01 and 0xffffffffu) + (x00 shr 32)
        val m2 = (x10 shr 32) + (x01 shr 32) + (x11 and 0xffffffffu) + (m1 shr 32)
        val m3 = (x11 shr 32) + (m2 shr 32)
        return ((m3 shl 32) + (m2 and 0xffffffffu)).toLong()
    }

    private fun smulh(a: Long, b: Long): Long {
        var h = umulh(a, b)
        if (a < 0) h -= b
        if (b < 0) h -= a
        return h
    }

    private fun rotr64(x: Long, c: Int): Long {
        val n = c and 63
        return if (n == 0) x else (x ushr n) or (x shl (64 - n))
    }

    private fun signExtend2s(x: Int): Long = x.toLong()

    fun execute(program: HashXProgram, r: LongArray) {
        require(r.size >= 8)
        var target = 0
        var branchEnable = true
        var result = 0L
        var i = 0
        while (i < program.codeSize) {
            val instr = program.code[i]
            when (instr.opcode) {
                HashXOpcode.UMULH_R -> {
                    r[instr.dst] = umulh(r[instr.dst], r[instr.src])
                    result = r[instr.dst] and 0xffff_ffffL
                }
                HashXOpcode.SMULH_R -> {
                    r[instr.dst] = smulh(r[instr.dst], r[instr.src])
                    result = r[instr.dst] and 0xffff_ffffL
                }
                HashXOpcode.MUL_R -> r[instr.dst] *= r[instr.src]
                HashXOpcode.SUB_R -> r[instr.dst] -= r[instr.src]
                HashXOpcode.XOR_R -> r[instr.dst] = r[instr.dst] xor r[instr.src]
                HashXOpcode.ADD_RS -> r[instr.dst] += r[instr.src] shl instr.imm32
                HashXOpcode.ROR_C -> r[instr.dst] = rotr64(r[instr.dst], instr.imm32)
                HashXOpcode.ADD_C -> r[instr.dst] += signExtend2s(instr.imm32)
                HashXOpcode.XOR_C -> r[instr.dst] = r[instr.dst] xor signExtend2s(instr.imm32)
                HashXOpcode.TARGET -> target = i
                HashXOpcode.BRANCH -> {
                    if (branchEnable && (result and (instr.imm32.toLong() and 0xffff_ffffL)) == 0L) {
                        i = target
                        branchEnable = false
                    }
                }
            }
            i++
        }
    }
}
