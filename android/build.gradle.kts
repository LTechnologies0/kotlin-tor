plugins {
    alias(libs.plugins.android.library)
}

configurations.configureEach {
    exclude(group = "org.conscrypt", module = "conscrypt-openjdk-uber")
}

android {
    namespace = "org.kotlintor.android"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    api(project(":core"))
    api(project(":control"))
    api(project(":proxy"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    // Per-ABI lib/<abi>/*.so. OpenJDK Conscrypt is excluded above.
    api(libs.conscrypt.android)
}
