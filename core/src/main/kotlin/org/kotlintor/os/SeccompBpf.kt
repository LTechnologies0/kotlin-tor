package org.kotlintor.os

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.ByteOrder

/**
 * Linux seccomp-bpf filter install via JDK 21 Panama FFM (no JNI .so).
 *
 * Installs a real `SECCOMP_MODE_FILTER` after best-effort `PR_SET_NO_NEW_PRIVS`.
 * Default program allows all syscalls (proves install path). Optional deny-ptrace
 * rule for x86_64 (`NR_ptrace=101`).
 *
 * Full Tor-style deny lists remain operator-tunable via [buildDenyPtraceFilter]
 * extensions; JVM hosts still need many syscalls.
 */
object SeccompBpf {
    const val PR_SET_NO_NEW_PRIVS: Long = 38
    const val PR_SET_SECCOMP: Long = 22
    const val SECCOMP_MODE_FILTER: Long = 2
    const val BPF_LD: Int = 0x00
    const val BPF_W: Int = 0x00
    const val BPF_ABS: Int = 0x20
    const val BPF_JMP: Int = 0x05
    const val BPF_JEQ: Int = 0x10
    const val BPF_K: Int = 0x00
    const val BPF_RET: Int = 0x06
    const val SECCOMP_RET_ALLOW: Int = 0x7fff0000
    const val SECCOMP_RET_KILL: Int = 0x00000000

    data class InstallResult(val installed: Boolean, val noNewPrivs: Boolean, val note: String)

    /** Classic sock_filter { code, jt, jf, k } — 8 bytes LE. */
    data class SockFilter(val code: Short, val jt: Byte, val jf: Byte, val k: Int)

    fun buildAllowAllFilter(): List<SockFilter> = listOf(
        SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, 4),
        SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, SECCOMP_RET_ALLOW),
    )

    /** Deny ptrace (syscall 101 on x86_64) then allow everything else. */
    fun buildDenyPtraceFilter(ptraceNr: Int = 101): List<SockFilter> = listOf(
        SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, 0),
        SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, ptraceNr),
        SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, SECCOMP_RET_KILL),
        SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, SECCOMP_RET_ALLOW),
    )

    /** Deny a set of dangerous x86_64 syscalls then ALLOW. */
    fun buildDenySyscallsFilter(denied: IntArray): List<SockFilter> {
        val out = mutableListOf<SockFilter>()
        out += SockFilter((BPF_LD or BPF_W or BPF_ABS).toShort(), 0, 0, 0)
        for (nr in denied) {
            // match → fall through to KILL; else skip the KILL insn
            out += SockFilter((BPF_JMP or BPF_JEQ or BPF_K).toShort(), 0, 1, nr)
            out += SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, SECCOMP_RET_KILL)
        }
        out += SockFilter((BPF_RET or BPF_K).toShort(), 0, 0, SECCOMP_RET_ALLOW)
        return out
    }

    /** Tor-inspired lite deny set (x86_64): ptrace, kexec_load, mount, reboot, swapon, init_module. */
    fun buildTorLiteDenyFilter(): List<SockFilter> = buildDenySyscallsFilter(
        intArrayOf(
            101, // ptrace
            246, // kexec_load
            165, // mount
            169, // reboot
            167, // swapon
            175, // init_module
        ),
    )

    fun packFilter(prog: List<SockFilter>): ByteArray {
        val out = ByteArray(prog.size * 8)
        for ((i, f) in prog.withIndex()) {
            val o = i * 8
            val code = f.code.toInt() and 0xffff
            out[o] = (code and 0xff).toByte()
            out[o + 1] = ((code ushr 8) and 0xff).toByte()
            out[o + 2] = f.jt
            out[o + 3] = f.jf
            val k = f.k
            out[o + 4] = (k and 0xff).toByte()
            out[o + 5] = ((k ushr 8) and 0xff).toByte()
            out[o + 6] = ((k ushr 16) and 0xff).toByte()
            out[o + 7] = ((k ushr 24) and 0xff).toByte()
        }
        return out
    }

    fun install(denyPtrace: Boolean = false): InstallResult {
        if (!System.getProperty("os.name", "").lowercase().contains("linux")) {
            return InstallResult(false, false, "seccomp: not Linux")
        }
        return try {
            Arena.ofConfined().use { arena ->
                val linker = Linker.nativeLinker()
                val prctlSym = linker.defaultLookup().find("prctl").orElse(null)
                    ?: return InstallResult(false, false, "seccomp: prctl symbol missing")
                val prctlMh: MethodHandle = linker.downcallHandle(
                    prctlSym,
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_LONG,
                    ),
                )
                val nnp = (prctlMh.invoke(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) as Int) == 0

                val filter = when {
                    denyPtrace -> buildTorLiteDenyFilter()
                    else -> buildAllowAllFilter()
                }
                val progBytes = packFilter(filter)
                val filterSeg = arena.allocate(progBytes.size.toLong())
                MemorySegment.copy(MemorySegment.ofArray(progBytes), 0, filterSeg, 0, progBytes.size.toLong())

                // struct sock_fprog { unsigned short len; padding; sock_filter *filter; }
                val fprogLayout = MemoryLayout.structLayout(
                    ValueLayout.JAVA_SHORT.withName("len"),
                    MemoryLayout.paddingLayout(6),
                    ValueLayout.ADDRESS.withName("filter"),
                )
                val fprog = arena.allocate(fprogLayout)
                fprog.set(ValueLayout.JAVA_SHORT, 0L, filter.size.toShort())
                fprog.set(ValueLayout.ADDRESS, 8L, filterSeg)

                val rc = prctlMh.invoke(
                    PR_SET_SECCOMP,
                    SECCOMP_MODE_FILTER,
                    fprog.address(),
                    0L,
                    0L,
                ) as Int
                if (rc == 0) {
                    InstallResult(true, nnp, "seccomp filter installed (${filter.size} insns)")
                } else {
                    InstallResult(false, nnp, "seccomp prctl failed rc=$rc")
                }
            }
        } catch (t: Throwable) {
            InstallResult(false, false, "seccomp FFM: ${t.javaClass.simpleName}: ${t.message}")
        }
    }
}
