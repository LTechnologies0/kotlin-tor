package org.kotlintor.pow

/** HashX instruction opcodes (instruction.h). */
enum class HashXOpcode {
    UMULH_R,
    SMULH_R,
    MUL_R,
    SUB_R,
    XOR_R,
    ADD_RS,
    ROR_C,
    ADD_C,
    XOR_C,
    TARGET,
    BRANCH,
}

data class HashXInstruction(
    var opcode: HashXOpcode = HashXOpcode.MUL_R,
    var src: Int = -1,
    var dst: Int = -1,
    var imm32: Int = 0,
    var opPar: Int = 0,
)

class HashXProgram {
    val code = Array(HASHX_PROGRAM_MAX_SIZE) { HashXInstruction() }
    var codeSize: Int = 0

    companion object {
        const val HASHX_PROGRAM_MAX_SIZE = 512
    }
}
