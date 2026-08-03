-keep class org.kotlintor.** { *; }

# Desktop/JVM-only APIs referenced from shared core (never used on Android paths).
# Without these, R8 fail-closes OnionVPN minifyReleaseWithR8.
-dontwarn java.lang.ProcessHandle
-dontwarn java.lang.foreign.**
-dontwarn org.kotlintor.os.SeccompBpf
-dontwarn org.kotlintor.os.SeccompBpf$*
-dontwarn org.kotlintor.config.PidFile
