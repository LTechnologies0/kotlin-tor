plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}

allprojects {
    group = "org.kotlintor"
    version = "0.1.0-SNAPSHOT"
}

tasks.register("checkAll") {
    dependsOn(
        ":core:check",
        ":control:check",
        ":proxy:check",
        ":cli:check",
        ":android:check",
    )
}
