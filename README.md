# DNSCrypt on Android

Standalone Android ARM64 APK, independent of [Awara](https://github.com/Grinch27/awara).
**Status: experimental. GitHub Actions compilation passed; Android device behavior and DNS leak prevention are not yet validated.**

## Build and install

- [GitHub Actions](https://github.com/Grinch27/DNSCrypt_on_Android/actions/workflows/build-apk.yml) builds a debug-signed APK on each `main` push and manual workflow dispatch.
- Download the `dnscrypt-experimental-arm64` artifact from a successful run. Unzip and locate `app-debug.apk`.
- Sideload manually to an ARM64 Android 10+ test device. App never changes Android system DNS, installs a VPN, or requires Root.
- Debug signing keys may differ on later builds. This is **not** a stable release signature.

## Use

Open app; select **Start OpenDNS DoH** for `doh.opendns.com`, or **Start Quad9 DNSCrypt** for four no-filter ECS servers.
Local endpoint: `127.0.0.1:15353` (UDP/TCP). Other apps must explicitly use this address; it is not system-wide DNS.
Use **Stop** before selecting another mode; **Refresh state** reads the last state.
Logs and config live in the private app directory. The first version intentionally uses locked TOML templates to avoid unsafe edits overriding the strict DNS policy.

## Security boundary and verification

- Builds from official dnscrypt-proxy `2.1.18` tagged commit `458d2af16a8ece668d9453a3293004bdd08158e7`; a small strict patch removes plaintext bootstrap and OS resolver fallback from `xtransport.resolve()`.
- OpenDNS static DoH stamp targets `146.112.41.2` with TLS name `doh.opendns.com`. The CI checks a real DoH query with `curl --resolve`, without a plaintext bootstrap request.
- Quad9 resolver list is downloaded by CI, Minisign-verified with its own key, bundled with signature, and reverified by the proxy when read. Refreshes fail closed.
- The Go executable is packaged as `libdnscryptproxy.so` inside `nativeLibraryDir`, but it remains an ELF **program**, not a JNI shared library. Android 10–17 execution is unconfirmed.
- CI fails if Go ELF `PT_LOAD` alignment is below 16KB or if APK packaging changes the ELF bytes.
- No Android device tests, actual listener/PID ownership tests, TCP tests, sleep/network transitions or packet capture have passed yet. A host CI success is **not proof** of zero DNS leakage.
- Android itself and other apps may still make independent DNS queries; no-VPN design cannot intercept them.

Toolchains: latest stable Go, Gradle and Android NDK selected at build time; AGP resolved from Google's stable Maven metadata; actual versions and APK SHA256 recorded in Actions artifacts. Upstream and third-party sources remain subject to their licenses.

No automated Play publishing or GitHub Release: this pipeline uploads an experimental Actions artifact only.
