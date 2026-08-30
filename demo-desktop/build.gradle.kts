plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.jetbrains.compose)
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":demo-common"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation(libs.kotlinx.coroutines.core)
}

/** Panama SO_MARK / TUN + reflective socket FD (SocksSocketImpl.delegate). */
val kotlinTorNativeJvmArgs = listOf(
    "--enable-preview",
    "--enable-native-access=ALL-UNNAMED",
    "--add-opens=java.base/java.net=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
)

compose.desktop {
    application {
        mainClass = "org.kotlintor.demo.desktop.MainKt"
        jvmArgs += kotlinTorNativeJvmArgs
        nativeDistributions {
            targetFormats(
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.AppImage,
            )
            packageName = "kotlin-tor-demo"
            packageVersion = "0.1.1"
            description = "kotlin-tor Material 3 demo (Linux full-tunnel VPN needs CAP_NET_ADMIN)"
            linux {
                packageName = "kotlin-tor-demo"
                menuGroup = "Network"
            }
        }
    }
}
