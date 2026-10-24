# LeapTerm

This is the public home for **LeapTerm client downloads** and **Leap Agent packages**.

## Download the app

Open **[Releases](https://github.com/omnisolo-llc/leapterm-release/releases)** to download the latest public release assets:

| Platform | File to look for |
| --- | --- |
| Windows x64 | `leapterm-<version>-windows-x64.zip` — portable desktop bundle |
| Linux x64 | `leapterm-<version>-linux-x64.tar.gz` — desktop bundle built on Ubuntu 24.04 |
| macOS Apple Silicon (13.5+) | `leapterm-<version>-macos-arm64.zip` — signed and notarized application bundle |
| Android | Universal APK (`leapterm-<version>-android-universal.apk`) and architecture-specific `armeabi-v7a`, `arm64-v8a`, and `x86_64` APKs |
| Linux agent | `leapterm-<version>-agent-linux-amd64.deb` and `leapterm-<version>-agent-linux-x86_64.rpm` |

Each downloadable package includes a `.sha256` checksum sidecar and a detached OpenPGP
signature (`.sha256.sig`), along with `SHA256SUMS`, `leapterm-package-signing-key.gpg`,
and the signed release provenance manifest `leapterm-<version>-release-provenance.json`.

When a release uses a self-signed Windows Authenticode certificate, its notes
disclose that choice. Windows may show trust warnings because the certificate
is not trusted by a public certificate authority. The Windows ZIP includes only
the public DER certificate, `leapterm-windows-signing.cer`. Verify the download's
detached OpenPGP signature using the release signing key before use.

## License

The public launcher and release workflow source use the [GPL-3.0 license](LICENSE).
Separately distributed application binaries retain their own license.

# Leap Agent Native Builds

Standalone Leap Agent builds support Linux, macOS, and Windows across x86-64 and ARM64:

| Standalone agent | Architectures | Supported download containers |
| --- | --- | --- |
| Linux | x86-64, ARM64 | ZIP, tar.gz, DEB, RPM |
| macOS | Intel x86-64, Apple Silicon ARM64 | ZIP, tar.gz, PKG, DMG |
| Windows | x86-64, ARM64 | portable EXE and ZIP, MSI, setup EXE |
