plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("org.kotlintor.cli.MainKt")
}

dependencies {
    implementation(project(":core"))
    implementation(project(":control"))
    implementation(project(":proxy"))
    implementation(libs.kotlinx.coroutines.core)
}

tasks.test {
    useJUnitPlatform()
}
