plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.jetbrains.compose) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}

allprojects {
    group = "org.kotlintor"
    version = "0.1.1"
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
