# DNSCrypt on Android

Standalone Android ARM64 APK, independent of [Awara](https://github.com/Grinch27/awara).
**Status: experimental DNS-only VPN. Android device behavior, Private DNS interaction and leak prevention are not yet validated.**

## Build and install

- [GitHub Actions](https://github.com/Grinch27/DNSCrypt_on_Android/actions/workflows/build-apk.yml) builds a debug-signed APK on each `main` push and manual workflow dispatch.
- Download the `DNSCrypt_on_Android-arm64-debug` artifact from a successful run. GitHub Actions automatically downloads artifacts as a ZIP; it now contains **exactly one file**: `DNSCrypt_on_Android-arm64-debug.apk` (no reports, source files, or additional folders). Extract and install that APK.
- Sideload manually to an ARM64 Android 10+ test device. App never changes Android system DNS, installs a VPN, or requires Root.
- Debug signing keys may differ on later builds. This is **not** a stable release signature.

## Use

Open app; select **Connect DNS-only VPN · OpenDNS DoH** for `doh.opendns.com`, or **Connect DNS-only VPN · Quad9 DNSCrypt** for four no-filter ECS servers. Accept the Android system VPN authorization dialog at first start. The status bar then displays a VPN icon if Android establishes the interface.
Local endpoint: `127.0.0.1:15353` (UDP/TCP). Other apps must explicitly support a custom DNS server address **and port**; it is not system-wide DNS. Android's Private DNS setting accepts a DoT hostname, **not** this local UDP/TCP endpoint.
Use **Disconnect VPN** before selecting another mode; **Refresh state** reads the last state. The VPN interface advertises synthetic DNS `10.111.0.1` and routes **only `10.111.0.1/32`** into TUN. The phone's ordinary network traffic is not tunneled. UDP DNS queries are bridged to `127.0.0.1:15353`; TCP DNS/53 is not yet supported and deliberately fails closed (large truncated DNS answers may fail). Other applications need no manual custom DNS port when their queries use Android's default resolver.
Logs and config live in the private app directory. The first version intentionally uses locked TOML templates to avoid unsafe edits overriding the strict DNS policy.

## Security boundary and verification

- Builds from official dnscrypt-proxy `2.1.18` tagged commit `458d2af16a8ece668d9453a3293004bdd08158e7`; a small strict patch removes plaintext bootstrap and OS resolver fallback from `xtransport.resolve()`.
- OpenDNS static DoH stamp targets `146.112.41.2` with TLS name `doh.opendns.com`. The CI checks a real DoH query with `curl --resolve`, without a plaintext bootstrap request.
- Quad9 resolver list is downloaded by CI, Minisign-verified with its own key, bundled with signature, and reverified by the proxy when read. Refreshes fail closed.
- The Go executable is packaged as `libdnscryptproxy.so` inside `nativeLibraryDir`, but it remains an ELF **program**, not a JNI shared library. Android 10–17 execution is unconfirmed.
- CI fails if Go ELF `PT_LOAD` alignment is below 16KB or if APK packaging changes the ELF bytes.
- No Android device tests, actual listener/PID ownership tests, TCP tests, sleep/network transitions or packet capture have passed yet. A host CI success is **not proof** of zero DNS leakage.
- Android Private DNS (DoT), apps with built-in encrypted DNS (DoH/DoT), IPv6 private DNS, direct-IP traffic and apps bypassing Android's resolver may not be captured. For initial manual validation, turn Android Private DNS **Off** (not Automatic) before VPN test; this is not a bypass of the proxy's TLS requirement.
- Android allows only one VPN per user/profile. Another VPN may disconnect; Android's "Always-on VPN / Block connections without VPN" settings require separate compatibility verification.
- If dnscrypt-proxy fails while the TUN is active, the app keeps its DNS-specific VPN route and drops queries. OS VPN revocation/service death removes that protection, so zero system-wide DNS leakage is **not** currently established.
- Current TUN only supports IPv4 UDP port 53 destined to the synthetic DNS IP; TCP DNS support, IPv6 transport and MTU overflow need further work.

Toolchains: latest stable Go, Gradle and Android NDK selected at build time; AGP resolved from Google's stable Maven metadata; actual versions and APK SHA256 recorded in Actions artifacts. Upstream and third-party sources remain subject to their licenses.

No automated Play publishing or GitHub Release: this pipeline uploads an experimental Actions artifact only.
