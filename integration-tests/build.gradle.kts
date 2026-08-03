plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    testImplementation(project(":core"))
    testImplementation(project(":control"))
    testImplementation(project(":proxy"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    val live = (findProperty("ktor.liveNetwork") as String?)?.toBoolean() == true ||
        (findProperty("kotlin.tor.liveNetwork") as String?)?.toBoolean() == true
    systemProperty("kotlin.tor.liveNetwork", live.toString())
    if (!live) {
        filter {
            excludeTestsMatching("*Live*")
        }
    }
}
