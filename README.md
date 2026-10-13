# OmniTerm

This is the public home for **OmniTerm client downloads**, **Omni Agent packages**, and the **self-hosted relay kit**.

## Run your own relay

The relay lets compatible OmniTerm clients and agents connect through your own
Cloudflare account or self-hosted infrastructure. You control the deployment and
its shared access token.

**[Follow the Cloudflare setup guide →](relay/cloudflare/README.md)**

For browser live-share over MoQ, deploy the HTTP/3 relay from
[relay/moq](relay/moq/README.md) and configure its HTTPS origin.

Use Node.js 24.21.0 or newer for the self-hosted relay kit. The Cloudflare guide covers installing
the tools, deploying the Worker, creating a fresh token, and checking connections.

## Download the app

Open **[Releases](https://github.com/omnisolo-llc/omniterm-release/releases)** to download the latest public release assets:

| Platform | File to look for |
| --- | --- |
| Windows x64 | `omniterm-<version>-windows-x64.zip` — portable desktop bundle |
| Linux x64 | `omniterm-<version>-linux-x64.tar.gz` — desktop bundle built on Ubuntu 24.04 |
| macOS Apple Silicon (13.5+) | `omniterm-<version>-macos-arm64.zip` — signed and notarized application bundle |
| Android | Universal APK (`omniterm-<version>-android-universal.apk`) and architecture-specific `armeabi-v7a`, `arm64-v8a`, and `x86_64` APKs |
| Linux agent | `omniterm-<version>-agent-linux-amd64.deb` and `omniterm-<version>-agent-linux-x86_64.rpm` |
| Self-hosted relay kit | `omniterm-<version>-self-hosted.zip` — Cloudflare, native, and MoQ relay sources |

Each downloadable package includes a `.sha256` checksum sidecar and a detached OpenPGP
signature (`.sha256.sig`), along with `SHA256SUMS`, `omniterm-package-signing-key.gpg`,
and the signed release provenance manifest `omniterm-<version>-release-provenance.json`.

When a release uses a self-signed Windows Authenticode certificate, its notes
disclose that choice. Windows may show trust warnings because the certificate
is not trusted by a public certificate authority. The Windows ZIP includes only
the public DER certificate, `omniterm-windows-signing.cer`. Verify the download's
detached OpenPGP signature using the release signing key before use.

## License

The public relay and launcher source use the [GPL-3.0 license](LICENSE).
Separately distributed application binaries retain their own license.

# Omni Agent Native Builds

Standalone Omni Agent builds support Linux, macOS, and Windows across x86-64 and ARM64:

| Standalone agent | Architectures | Supported download containers |
| --- | --- | --- |
| Linux | x86-64, ARM64 | ZIP, tar.gz, DEB, RPM |
| macOS | Intel x86-64, Apple Silicon ARM64 | ZIP, tar.gz, PKG, DMG |
| Windows | x86-64, ARM64 | portable EXE and ZIP, MSI, setup EXE |
