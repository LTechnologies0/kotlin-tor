pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "kotlin-tor"

include(
    ":core",
    ":control",
    ":proxy",
    ":cli",
    ":android",
)
// Optional apps/tests — omit by default so OnionVPN includeBuild does not configure
// AGP application modules (kotlin extension clashes under composite builds).
if (providers.gradleProperty("kotlin.tor.extras").orNull == "true") {
    include(":demo-router", ":integration-tests")
}
