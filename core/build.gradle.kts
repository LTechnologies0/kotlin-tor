plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.coroutines.jdk8)
    api(libs.bouncycastle.provider)
    api(libs.bouncycastle.pkix)
    implementation(libs.conscrypt.openjdk)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.ktor.network)
    implementation(libs.ktor.network.tls)
    implementation(libs.zstd.jni)
    implementation(libs.xz)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
