package org.kotlintor.os

/**
 * Windows service install helpers (C Tor WinService analogue).
 *
 * Ships a WinSW-compatible XML service definition operators can register with
 * [WinSW](https://github.com/winsw/winsw) or `sc.exe`. The JVM process itself
 * does not embed a native service main — packaging wires the CLI entrypoint.
 */
object WinService {
    const val SERVICE_ID = "kotlin-tor"
    const val DISPLAY_NAME = "kotlin-tor Tor client/relay"

    /** WinSW XML for wrapping `java -jar cli.jar -f torrc`. */
    fun winswXml(
        javaHome: String = "%JAVA_HOME%",
        jarPath: String = "C:\\Program Files\\kotlin-tor\\cli.jar",
        torrcPath: String = "C:\\ProgramData\\kotlin-tor\\torrc",
        logDir: String = "C:\\ProgramData\\kotlin-tor\\logs",
    ): String = """
        |<service>
        |  <id>$SERVICE_ID</id>
        |  <name>$DISPLAY_NAME</name>
        |  <description>Pure-Kotlin Tor implementation (kotlin-tor)</description>
        |  <executable>$javaHome\bin\java.exe</executable>
        |  <arguments>-jar "$jarPath" -f "$torrcPath"</arguments>
        |  <logpath>$logDir</logpath>
        |  <log mode="roll-by-size">
        |    <sizeThreshold>10240</sizeThreshold>
        |    <keepFiles>8</keepFiles>
        |  </log>
        |  <onfailure action="restart" delay="10 sec"/>
        |  <stoptimeout>15 sec</stoptimeout>
        |</service>
        """.trimMargin()

    /** `sc create` command line (run elevated). */
    fun scCreateCommand(
        binPath: String = "C:\\Program Files\\kotlin-tor\\kotlin-tor-service.exe",
    ): String =
        "sc create $SERVICE_ID binPath= \"$binPath\" start= auto DisplayName= \"$DISPLAY_NAME\""
}
