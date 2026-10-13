// TODO: ELF-as-native-library packaging is experimental on Android 10–17.
// Risk: a Go PIE executable is not a JNI library; nativeLibraryDir execution must pass device tests.
// Verification: the APK ELF must match the verified built executable byte-for-byte.
plugins { id("com.android.application") }

android {
    namespace = "com.grinch27.dnscrypt"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.grinch27.dnscrypt"
        minSdk = 29
        targetSdk = 37
        versionCode = 2
        versionName = "0.2.0-dns-only-vpn-experimental"
        ndk { abiFilters.add("arm64-v8a") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/libdnscryptproxy.so"
        }
    }
}
val verifyNativePayload = tasks.register("verifyNativePayload") {
    doLast {
        val native = file("src/main/jniLibs/arm64-v8a/libdnscryptproxy.so")
        val list = file("src/main/assets/quad9-resolvers.md")
        val signature = file("src/main/assets/quad9-resolvers.md.minisig")
        check(native.isFile && native.length() > 0) { "Missing verified ARM64 dnscrypt-proxy ELF" }
        check(list.isFile && signature.isFile) { "Missing Minisign-verified Quad9 list" }
    }
}
tasks.named("preBuild") { dependsOn(verifyNativePayload) }
