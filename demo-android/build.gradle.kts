import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "org.kotlintor.demo.android"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "org.kotlintor.demo.android"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = rootProject.version.toString().substringBefore("-")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    signingConfigs {
        create("release") {
            applyReleaseSigning(this)
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.storeFile?.let {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    buildFeatures {
        viewBinding = true
    }

    lint {
        checkReleaseBuilds = false
    }

    packaging {
        resources {
            // BouncyCastle (bcprov/bcpkix/bcutil) each ship META-INF/LICENSE.md + NOTICE.md.
            excludes += setOf(
                "META-INF/LICENSE.md",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE.md",
                "META-INF/NOTICE.txt",
            )
        }
    }
}

dependencies {
    implementation(project(":demo-common"))
    implementation(project(":android"))
    implementation(libs.androidx.core.ktx)
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.2")
    implementation("androidx.drawerlayout:drawerlayout:1.2.0")
    implementation("androidx.coordinatorlayout:coordinatorlayout:1.3.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.1")
    implementation(libs.kotlinx.coroutines.core)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}

/**
 * Release signing from CI env vars, or a local `keystore.properties` (gitignored).
 *
 * Env (GitHub Actions):
 *   ANDROID_KEYSTORE_FILE, ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS,
 *   ANDROID_KEY_PASSWORD (optional; defaults to store password)
 *
 * keystore.properties:
 *   storeFile, storePassword, keyAlias, keyPassword
 */
fun applyReleaseSigning(config: com.android.build.api.dsl.SigningConfig) {
    val envStore = System.getenv("ANDROID_KEYSTORE_FILE")
    if (!envStore.isNullOrBlank()) {
        val storePasswordEnv = System.getenv("ANDROID_KEYSTORE_PASSWORD")
        val aliasEnv = System.getenv("ANDROID_KEY_ALIAS")
        val keyPasswordEnv = System.getenv("ANDROID_KEY_PASSWORD").orEmpty().ifBlank { storePasswordEnv }
        require(!storePasswordEnv.isNullOrBlank()) { "ANDROID_KEYSTORE_PASSWORD is required when ANDROID_KEYSTORE_FILE is set" }
        require(!aliasEnv.isNullOrBlank()) { "ANDROID_KEY_ALIAS is required when ANDROID_KEYSTORE_FILE is set" }
        config.storeFile = file(envStore)
        config.storePassword = storePasswordEnv
        config.keyAlias = aliasEnv
        config.keyPassword = keyPasswordEnv
        return
    }

    val propsFile = rootProject.file("keystore.properties")
    if (!propsFile.isFile) {
        return
    }
    val props = Properties().apply {
        propsFile.inputStream().use { load(it) }
    }
    val storePath = props.getProperty("storeFile")
        ?: error("keystore.properties is missing storeFile")
    config.storeFile = rootProject.file(storePath)
    config.storePassword = props.getProperty("storePassword")
        ?: error("keystore.properties is missing storePassword")
    config.keyAlias = props.getProperty("keyAlias")
        ?: error("keystore.properties is missing keyAlias")
    config.keyPassword = props.getProperty("keyPassword")
        ?: config.storePassword
}
