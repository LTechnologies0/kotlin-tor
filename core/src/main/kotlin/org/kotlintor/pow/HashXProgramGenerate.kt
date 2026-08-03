package org.kotlintor.pow

/**
 * Faithful Kotlin port of tevador HashX `program.c` (program generation).
 */
object HashXProgramGenerate {
    private const val TARGET_CYCLE = 192
    private const val REQUIREMENT_SIZE = 512
    private const val REQUIREMENT_MUL_COUNT = 192
    private const val REQUIREMENT_LATENCY = 195
    private const val REGISTER_NEEDS_DISPLACEMENT = 5
    private const val PORT_MAP_SIZE = TARGET_CYCLE + 4
    private const val NUM_PORTS = 3
    private const val MAX_RETRIES = 1
    private const val LOG2_BRANCH_PROB = 4
    private const val BRANCH_MASK = 0x80000000.toInt()

    private const val PORT_NONE = 0
    private const val PORT_P0 = 1
    private const val PORT_P1 = 2
    private const val PORT_P5 = 4
    private const val PORT_P01 = PORT_P0 or PORT_P1
    private const val PORT_P05 = PORT_P0 or PORT_P5
    private const val PORT_P015 = PORT_P0 or PORT_P1 or PORT_P5

    private class InstrTemplate(
        val type: HashXOpcode,
        val latency: Int,
        val uop1: Int,
        val uop2: Int,
        val immediateMask: Int,
        val group: HashXOpcode,
        val immCanBe0: Boolean,
        val distinctDst: Boolean,
        val opParSrc: Boolean,
        val hasSrc: Boolean,
        val hasDst: Boolean,
    )

    private class RegisterInfo(
        var latency: Int = 0,
        var lastOp: Int = -1,
        var lastOpPar: Int = -1,
    )

    private class ProgramItem(
        val templates: Array<InstrTemplate>,
        val mask0: Int,
        val mask1: Int,
        val duplicates: Boolean,
    )

    private class GeneratorCtx {
        var cycle = 0
        var subCycle = 0
        var mulCount = 0
        var chainMul = false
        var latency = 0
        val gen = SipHashRng()
        val registers = Array(8) { RegisterInfo() }
        val ports = Array(PORT_MAP_SIZE) { IntArray(NUM_PORTS) }
    }

    private val tplUmulhR = InstrTemplate(HashXOpcode.UMULH_R, 4, PORT_P1, PORT_P5, 0, HashXOpcode.UMULH_R, false, false, false, true, true)
    private val tplSmulhR = InstrTemplate(HashXOpcode.SMULH_R, 4, PORT_P1, PORT_P5, 0, HashXOpcode.SMULH_R, false, false, false, true, true)
    private val tplMulR = InstrTemplate(HashXOpcode.MUL_R, 3, PORT_P1, PORT_NONE, 0, HashXOpcode.MUL_R, false, true, true, true, true)
    private val tplSubR = InstrTemplate(HashXOpcode.SUB_R, 1, PORT_P015, PORT_NONE, 0, HashXOpcode.ADD_RS, false, true, true, true, true)
    private val tplXorR = InstrTemplate(HashXOpcode.XOR_R, 1, PORT_P015, PORT_NONE, 0, HashXOpcode.XOR_R, false, true, true, true, true)
    private val tplAddRs = InstrTemplate(HashXOpcode.ADD_RS, 1, PORT_P01, PORT_NONE, 3, HashXOpcode.ADD_RS, true, true, true, true, true)
    private val tplRorC = InstrTemplate(HashXOpcode.ROR_C, 1, PORT_P05, PORT_NONE, 63, HashXOpcode.ROR_C, false, true, false, false, true)
    private val tplAddC = InstrTemplate(HashXOpcode.ADD_C, 1, PORT_P015, PORT_NONE, -1, HashXOpcode.ADD_C, false, true, false, false, true)
    private val tplXorC = InstrTemplate(HashXOpcode.XOR_C, 1, PORT_P015, PORT_NONE, -1, HashXOpcode.XOR_C, false, true, false, false, true)
    private val tplTarget = InstrTemplate(HashXOpcode.TARGET, 1, PORT_P015, PORT_P015, 0, HashXOpcode.TARGET, false, true, false, false, false)
    private val tplBranch = InstrTemplate(HashXOpcode.BRANCH, 1, PORT_P015, PORT_P015, BRANCH_MASK, HashXOpcode.BRANCH, false, true, false, false, false)

    private val instrLookup = arrayOf(tplRorC, tplXorC, tplAddC, tplAddC, tplSubR, tplXorR, tplXorC, tplAddRs)
    private val wideMulLookup = arrayOf(tplSmulhR, tplUmulhR)

    private val itemMul = ProgramItem(arrayOf(tplMulR), 0, 0, true)
    private val itemTarget = ProgramItem(arrayOf(tplTarget), 0, 0, true)
    private val itemBranch = ProgramItem(arrayOf(tplBranch), 0, 0, true)
    private val itemWideMul = ProgramItem(wideMulLookup, 1, 1, true)
    private val itemAny = ProgramItem(instrLookup, 7, 3, false)

    private val programLayout = arrayOf(
        itemMul, itemTarget, itemAny, itemMul, itemAny, itemAny, itemMul, itemAny, itemAny, itemMul,
        itemAny, itemAny, itemWideMul, itemAny, itemAny, itemMul, itemAny, itemAny, itemMul, itemBranch,
        itemAny, itemMul, itemAny, itemAny, itemWideMul, itemAny, itemAny, itemMul, itemAny, itemAny,
        itemMul, itemAny, itemAny, itemMul, itemAny, itemAny,
    )

    private fun isMul(type: HashXOpcode): Boolean =
        type == HashXOpcode.UMULH_R || type == HashXOpcode.SMULH_R || type == HashXOpcode.MUL_R

    private fun selectTemplate(ctx: GeneratorCtx, lastInstr: Int, attempt: Int): InstrTemplate {
        val item = programLayout[ctx.subCycle % 36]
        var tpl: InstrTemplate
        do {
            val index = if (item.mask0 != 0) {
                ctx.gen.u8() and (if (attempt > 0) item.mask1 else item.mask0)
            } else 0
            tpl = item.templates[index]
        } while (!item.duplicates && tpl.group.ordinal == lastInstr)
        return tpl
    }

    private fun branchMask(gen: SipHashRng): Int {
        var mask = 0
        var popcnt = 0
        while (popcnt < LOG2_BRANCH_PROB) {
            val bit = gen.u8() % 32
            val bitmask = 1 shl bit
            if ((mask and bitmask) == 0) {
                mask = mask or bitmask
                popcnt++
            }
        }
        return mask
    }

    private fun instrFromTemplate(tpl: InstrTemplate, gen: SipHashRng, instr: HashXInstruction) {
        instr.opcode = tpl.type
        if (tpl.immediateMask != 0) {
            if (tpl.immediateMask == BRANCH_MASK) {
                instr.imm32 = branchMask(gen)
            } else {
                do {
                    instr.imm32 = gen.u32() and tpl.immediateMask
                } while (instr.imm32 == 0 && !tpl.immCanBe0)
            }
        }
        if (!tpl.opParSrc) {
            instr.opPar = if (tpl.distinctDst) -1 else gen.u32()
        }
        if (!tpl.hasSrc) instr.src = -1
        if (!tpl.hasDst) instr.dst = -1
    }

    private fun selectRegister(availableRegs: IntArray, regsCount: Int, gen: SipHashRng): Int? {
        if (regsCount == 0) return null
        val index = if (regsCount > 1) Integer.remainderUnsigned(gen.u32(), regsCount) else 0
        return availableRegs[index]
    }

    private fun selectDestination(tpl: InstrTemplate, instr: HashXInstruction, ctx: GeneratorCtx, cycle: Int): Boolean {
        val availableRegs = IntArray(8)
        var regsCount = 0
        for (i in 0 until 8) {
            var available = ctx.registers[i].latency <= cycle
            available = available && ((!tpl.distinctDst) || (i != instr.src))
            available = available && (ctx.chainMul || tpl.group != HashXOpcode.MUL_R || ctx.registers[i].lastOp != HashXOpcode.MUL_R.ordinal)
            available = available && (ctx.registers[i].lastOp != tpl.group.ordinal || ctx.registers[i].lastOpPar != instr.opPar)
            available = available && (instr.opcode != HashXOpcode.ADD_RS || i != REGISTER_NEEDS_DISPLACEMENT)
            if (available) availableRegs[regsCount++] = i
        }
        val reg = selectRegister(availableRegs, regsCount, ctx.gen) ?: return false
        instr.dst = reg
        return true
    }

    private fun selectSource(tpl: InstrTemplate, instr: HashXInstruction, ctx: GeneratorCtx, cycle: Int): Boolean {
        val availableRegs = IntArray(8)
        var regsCount = 0
        for (i in 0 until 8) {
            if (ctx.registers[i].latency <= cycle) availableRegs[regsCount++] = i
        }
        if (regsCount == 2 && instr.opcode == HashXOpcode.ADD_RS) {
            if (availableRegs[0] == REGISTER_NEEDS_DISPLACEMENT || availableRegs[1] == REGISTER_NEEDS_DISPLACEMENT) {
                instr.opPar = REGISTER_NEEDS_DISPLACEMENT
                instr.src = REGISTER_NEEDS_DISPLACEMENT
                return true
            }
        }
        val reg = selectRegister(availableRegs, regsCount, ctx.gen) ?: return false
        instr.src = reg
        if (tpl.opParSrc) instr.opPar = instr.src
        return true
    }

    private fun scheduleUop(uop: Int, ctx: GeneratorCtx, startCycle: Int, commit: Boolean): Int {
        var cycle = startCycle
        while (cycle < PORT_MAP_SIZE) {
            if ((uop and PORT_P5) != 0 && ctx.ports[cycle][2] == 0) {
                if (commit) ctx.ports[cycle][2] = uop
                return cycle
            }
            if ((uop and PORT_P0) != 0 && ctx.ports[cycle][0] == 0) {
                if (commit) ctx.ports[cycle][0] = uop
                return cycle
            }
            if ((uop and PORT_P1) != 0 && ctx.ports[cycle][1] == 0) {
                if (commit) ctx.ports[cycle][1] = uop
                return cycle
            }
            cycle++
        }
        return -1
    }

    private fun scheduleInstr(tpl: InstrTemplate, ctx: GeneratorCtx, commit: Boolean): Int {
        if (tpl.uop2 == PORT_NONE) return scheduleUop(tpl.uop1, ctx, ctx.cycle, commit)
        for (cycle in ctx.cycle until PORT_MAP_SIZE) {
            val cycle1 = scheduleUop(tpl.uop1, ctx, cycle, false)
            val cycle2 = scheduleUop(tpl.uop2, ctx, cycle, false)
            if (cycle1 >= 0 && cycle1 == cycle2) {
                if (commit) {
                    scheduleUop(tpl.uop1, ctx, cycle, true)
                    scheduleUop(tpl.uop2, ctx, cycle, true)
                }
                return cycle1
            }
        }
        return -1
    }

    fun generate(key: SipHashState, program: HashXProgram): Boolean {
        val ctx = GeneratorCtx()
        ctx.gen.init(key)
        for (i in 0 until 8) {
            ctx.registers[i].lastOp = -1
            ctx.registers[i].latency = 0
            ctx.registers[i].lastOpPar = -1
        }
        program.codeSize = 0
        var attempt = 0
        var lastInstr = -1

        while (program.codeSize < HashXProgram.HASHX_PROGRAM_MAX_SIZE) {
            val instr = program.code[program.codeSize]
            val tpl = selectTemplate(ctx, lastInstr, attempt)
            lastInstr = tpl.group.ordinal
            instrFromTemplate(tpl, ctx.gen, instr)

            var scheduleCycle = scheduleInstr(tpl, ctx, false)
            if (scheduleCycle < 0) break

            ctx.chainMul = attempt > 0

            if (tpl.hasSrc) {
                if (!selectSource(tpl, instr, ctx, scheduleCycle)) {
                    if (attempt++ < MAX_RETRIES) continue
                    ctx.subCycle += 3
                    ctx.cycle = ctx.subCycle / 3
                    attempt = 0
                    continue
                }
            }
            if (tpl.hasDst) {
                if (!selectDestination(tpl, instr, ctx, scheduleCycle)) {
                    if (attempt++ < MAX_RETRIES) continue
                    ctx.subCycle += 3
                    ctx.cycle = ctx.subCycle / 3
                    attempt = 0
                    continue
                }
            }
            attempt = 0

            scheduleCycle = scheduleInstr(tpl, ctx, true)
            if (scheduleCycle < 0) break
            if (scheduleCycle >= TARGET_CYCLE) break

            if (tpl.hasDst) {
                val ri = ctx.registers[instr.dst]
                val retireCycle = scheduleCycle + tpl.latency
                ri.latency = retireCycle
                ri.lastOp = tpl.group.ordinal
                ri.lastOpPar = instr.opPar
                if (retireCycle > ctx.latency) ctx.latency = retireCycle
            }

            program.codeSize++
            if (isMul(instr.opcode)) ctx.mulCount++

            ctx.subCycle++
            if (tpl.uop2 != PORT_NONE) ctx.subCycle++
            ctx.cycle = ctx.subCycle / 3
        }

        return program.codeSize == REQUIREMENT_SIZE &&
            ctx.mulCount == REQUIREMENT_MUL_COUNT &&
            ctx.latency == REQUIREMENT_LATENCY - 1
    }
}
