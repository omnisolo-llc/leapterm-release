# Native public release launcher

Standalone Rust 1.95.0 launcher with a committed lockfile and a thin Bash wrapper.

## Commands

- `bash ci/native-release/run.sh validate-request`
- `bash ci/native-release/run.sh resolve`
- `bash ci/native-release/run.sh run`
- `bash ci/native-release/run.sh agent-source`
- `bash ci/native-release/run.sh agent-run`
- `bash ci/native-release/run.sh verify-agent-handoff --directory PATH --version VERSION --platform PLATFORM`
- `bash ci/native-release/run.sh verify-source --root PATH --sha SHA`
- `bash ci/native-release/run.sh verify-ios`
- `bash ci/native-release/run.sh windows-sdk`
- `bash ci/native-release/run.sh retain-artifacts`
- `bash ci/native-release/run.sh publish-candidates --directory PATH --plan PATH`

## Private staging

`publish-candidates` uses the Plan retained by trusted native preparation. The
private release is bound to its version, source revision and canonical Plan hash,
which includes the builder, request, run, attempt and exact file inventory.
Conflicting same-version drafts and published releases fail before any write.
An identical published release requires fresh metadata and downloaded-byte
verification. An owned partial draft retains its original asset IDs and uploads
only missing Plan files, with fresh ownership checks before every mutation.
Uncertain create, upload and promotion results are resolved through exact
readback; an unverified result preserves the original error.

This Plan covers the approved public candidate files staged privately. Complete
final private archive composition, including IPA files and diagnostics, requires
the authoritative retained private inventory and remains a separate pipeline
handoff. Native catalogue, signer and selected storage policy determine that
inventory and its classification.

## Verification

Run `bash ci/test-native-release.sh` to execute the launcher unit and contract tests, formatting check, and clippy lints.
The `private_staging` integration suite uses actual loopback HTTP with synthetic
identities and archives; it exercises staging behavior without provider
credentials or native signing. It does not qualify a native release or prove
complete final private archive composition.
