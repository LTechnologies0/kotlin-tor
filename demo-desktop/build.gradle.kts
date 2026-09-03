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
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.Msi,
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.Exe,
            )
            packageName = "kotlin-tor-demo"
            packageVersion = rootProject.version.toString().substringBefore("-")
            description = "kotlin-tor Material 3 demo (Linux full-tunnel VPN needs CAP_NET_ADMIN)"
            linux {
                packageName = "kotlin-tor-demo"
                menuGroup = "Network"
            }
            windows {
                menuGroup = "Network"
                dirChooser = true
                perUserInstall = true
                // Stable MSI upgrade code — do not change between releases of the same product.
                upgradeUuid = "a7c3e9d1-2f4b-4e18-9c6a-5d8b1f0e3a27"
            }
        }
    }
}
