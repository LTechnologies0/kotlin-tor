package org.kotlintor.os

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * Process hardening (torrc `Sandbox 1` analogue).
 *
 * Layers applied without JNI:
 * 1. Owner-only perms on [dataDirectory]
 * 2. Best-effort `prctl --no-new-privs` CLI
 * 3. Soft RLIMIT_NOFILE / RLIMIT_NPROC via `prlimit` when available
 * 4. Real seccomp-bpf via Panama FFM ([SeccompBpf]) when [enableSeccomp]
 * 5. Sandbox marker file for operators
 */
object LinuxSandbox {
    data class Result(
        val dataDirHardened: Boolean,
        val noNewPrivs: Boolean,
        val rlimits: Boolean,
        val seccomp: Boolean,
        val notes: List<String>,
    )

    fun apply(
        dataDirectory: Path,
        enableNoNewPrivs: Boolean = true,
        maxOpenFiles: Long = 4096,
        maxProcesses: Long = 512,
        enableSeccomp: Boolean = true,
        denyPtrace: Boolean = false,
    ): Result {
        val notes = mutableListOf<String>()
        var dirOk = false
        var nnp = false
        var rlim = false
        var seccompOk = false

        runCatching {
            Files.createDirectories(dataDirectory)
            val perms = setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            )
            Files.setPosixFilePermissions(dataDirectory, perms)
            dirOk = true
        }.onFailure { notes += "dataDir perms: ${it.message}" }

        if (enableNoNewPrivs) {
            nnp = runTool("prctl", "--no-new-privs=1", "true")
            if (!nnp) notes += "prctl no_new_privs unavailable"
        }

        val pid = ProcessHandle.current().pid()
        rlim = runTool("prlimit", "--pid=$pid", "--nofile=$maxOpenFiles:$maxOpenFiles") ||
            runTool("prlimit", "--pid=$pid", "--nproc=$maxProcesses:$maxProcesses")
        if (!rlim) notes += "prlimit unavailable"

        if (enableSeccomp) {
            val sc = SeccompBpf.install(denyPtrace = denyPtrace)
            seccompOk = sc.installed
            if (sc.noNewPrivs) nnp = true
            notes += sc.note
        }

        runCatching {
            Files.writeString(
                dataDirectory.resolve(".kotlin-tor-sandbox"),
                buildString {
                    appendLine("mode=seccomp-ffm")
                    appendLine("nofile=$maxOpenFiles")
                    appendLine("nproc=$maxProcesses")
                    appendLine("seccomp=$seccompOk")
                    appendLine("deny_ptrace=$denyPtrace")
                },
            )
        }.onFailure { notes += "marker: ${it.message}" }

        return Result(dirOk, nnp, rlim, seccompOk, notes)
    }

    private fun runTool(vararg args: String): Boolean =
        runCatching {
            val pb = ProcessBuilder(*args).redirectErrorStream(true)
            pb.start().waitFor() == 0
        }.getOrDefault(false)
}
