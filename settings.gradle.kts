// TODO: Verify latest stable AGP/Gradle compatibility on every CI build; no repository mutation by CI.
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "DNSCryptOnAndroid"
include(":app")
