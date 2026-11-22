//! Unattended fail-closed pre-release full test + E2E gate for
//! `nightly-testflight.yml`. Reuses the exact same private source checkout,
//! credential stripping, `env -i` toolchain compilation, clean `ci_child_environment`,
//! 13-stage `leap-release ci` execution, and encrypted diagnostic sealing as
//! `source-ci.yml`, without leaking private source paths, logs, or secrets.
use crate::{
    Environment, Result,
    ci_request::{BUILDER_REPOSITORY, CI_STAGES, PipelineIdentity, SourceCiRequest},
    clean_environment, guards,
    input::{positive_number, valid_repo_slug, valid_sha},
    launch, process, source, source_api, source_handoff,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub const NIGHTLY_WORKFLOW: &str =
    "omnisolo-llc/leapterm-release/.github/workflows/nightly-testflight.yml@refs/heads/main";

fn required<'a>(env: &'a Environment, key: &str) -> Result<&'a str> {
    env.get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Missing pre-release CI configuration")
}

/// Strictly bind pre-release CI execution to `nightly-testflight.yml` on
/// `omnisolo-llc/leapterm-release` `refs/heads/main` triggered by `schedule`
/// or `workflow_dispatch`.
pub fn require_nightly_origin(env: &Environment) -> Result<()> {
    let event = required(env, "GITHUB_EVENT_NAME")?;
    if !["schedule", "workflow_dispatch"].contains(&event) {
        return Err("Pre-release CI requires schedule or workflow_dispatch");
    }
    for (key, expected) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_REPOSITORY", BUILDER_REPOSITORY),
        ("GITHUB_WORKFLOW_REF", NIGHTLY_WORKFLOW),
    ] {
        if env.get(key).map(String::as_str) != Some(expected) {
            return Err("Pre-release CI origin is not authorized");
        }
    }
    if !valid_sha(required(env, "GITHUB_SHA")?)
        || !positive_number(required(env, "GITHUB_RUN_ID")?, 32)
        || !positive_number(required(env, "GITHUB_RUN_ATTEMPT")?, 16)
        || !valid_repo_slug(required(env, "SOURCE_REPOSITORY")?)
        || required(env, "SOURCE_BRANCH")? != "main"
    {
        return Err("Invalid pre-release CI run identity");
    }
    Ok(())
}

/// Deterministic opaque 24-hex fingerprint binding `(source_sha, builder_sha, catalog_sha256)`.
/// Matches `computeNightlyGateFingerprint` in `ci/nightly-testflight-dispatch.mjs`.
pub fn gate_fingerprint(
    source_sha: &str,
    builder_sha: &str,
    catalog_sha256: &str,
) -> Result<String> {
    if !valid_sha(source_sha) || !valid_sha(builder_sha) || !source_api::hash(catalog_sha256) {
        return Err("Invalid pre-release CI gate fingerprint inputs");
    }
    let payload = format!("leap-nightly-ci-gate-v1:{source_sha}:{builder_sha}:{catalog_sha256}");
    let full = format!("{:x}", Sha256::digest(payload.as_bytes()));
    Ok(full[..24].to_owned())
}

fn audit_nightly_workflow() -> Result<()> {
    let builder_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| "Builder root unavailable")?;
    let policy = crate::json::parse(
        &fs::read(builder_root.join("ci/standard-runner-policy.json"))
            .map_err(|_| "Runner policy unavailable")?,
    )?;
    let audit = crate::runner_policy::audit_workflows(
        &builder_root.join(".github/workflows/nightly-testflight.yml"),
        &policy,
    )?;
    if !audit["findings"].as_array().is_some_and(Vec::is_empty) {
        return Err("Nightly pre-release CI workflow policy refused");
    }
    Ok(())
}

fn validate_checkout_credentials(env: &Environment) -> Result<(&str, &str)> {
    let key_data = required(env, "SOURCE_DEPLOY_KEY")?;
    let hosts = required(env, "SOURCE_KNOWN_HOSTS")?;
    if key_data.len() > 32768
        || !key_data.trim_start().starts_with("-----BEGIN ")
        || !key_data.contains("PRIVATE KEY-----")
        || hosts.len() > 65536
    {
        return Err("Invalid pre-release CI checkout credential format");
    }
    Ok((key_data, hosts))
}

fn acquire_private_main_source(
    env: &Environment,
    root: &Path,
    src: &Path,
    requested_sha: &str,
    builder_sha: &str,
    resolve_predecessor: bool,
) -> Result<(String, Option<String>)> {
    let (key_data, hosts) = validate_checkout_credentials(env)?;
    let key = root.join("identity");
    let known = root.join("known_hosts");
    let website_key = root.join("website-identity");
    launch::private_file(
        &key,
        format!("{}\n", key_data.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    launch::private_file(
        &known,
        format!("{}\n", hosts.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    let result = (|| {
        let mut acquisition = launch::checkout_environment(env, &key, &known)?;
        acquisition.insert(
            "NATIVE_GIT_LOG".into(),
            root.join("bootstrap.log").to_string_lossy().into_owned(),
        );
        let website = env
            .get("SOURCE_SUBMODULE_DEPLOY_KEY_BASE64")
            .filter(|value| !value.is_empty())
            .map(|value| -> Result<Environment> {
                launch::private_file(&website_key, &launch::decode_submodule_key(value)?)?;
                launch::checkout_environment(env, &website_key, &known)
            })
            .transpose()?;
        let origin_url = format!(
            "ssh://git@ssh.github.com:443/{}.git",
            required(env, "SOURCE_REPOSITORY")?
        );
        for args in [
            vec!["init".into(), "-q".into()],
            vec!["config".into(), "core.autocrlf".into(), "false".into()],
            vec!["remote".into(), "add".into(), "origin".into(), origin_url],
        ] {
            source::git(src, &args, &acquisition)?;
        }
        source::git(
            src,
            &[
                "-c".into(),
                "protocol.ssh.allow=always".into(),
                "fetch".into(),
                "--quiet".into(),
                "--no-tags".into(),
                "origin".into(),
                "+refs/heads/main:refs/remotes/origin/reviewed".into(),
            ],
            &acquisition,
        )?;
        let resolved = source::resolve_revision(src, requested_sha, &acquisition)?;
        let predecessor = if resolve_predecessor {
            let configured = env
                .get("SOURCE_CI_AGENT_PREDECESSOR_SHA")
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty());
            let candidate = if let Some(explicit) = configured {
                if !valid_sha(&explicit) || explicit == resolved {
                    return Err("Invalid pre-release agent predecessor SHA");
                }
                source::git(
                    src,
                    &[
                        "merge-base".into(),
                        "--is-ancestor".into(),
                        explicit.clone(),
                        resolved.clone(),
                    ],
                    &acquisition,
                )?;
                explicit
            } else {
                let raw = source::git(
                    src,
                    &[
                        "rev-parse".into(),
                        "--verify".into(),
                        format!("{resolved}~1"),
                    ],
                    &acquisition,
                )?;
                let parent_sha = String::from_utf8(raw)
                    .map_err(|_| "Invalid predecessor commit metadata")?
                    .trim()
                    .to_ascii_lowercase();
                if !valid_sha(&parent_sha) || parent_sha == resolved {
                    return Err("Predecessor commit unavailable for agent-lifecycle stage");
                }
                parent_sha
            };
            Some(candidate)
        } else {
            None
        };
        source::git(
            src,
            &[
                "checkout".into(),
                "--quiet".into(),
                "--detach".into(),
                resolved.clone(),
            ],
            &acquisition,
        )?;
        let checkout = clean_environment(env);
        source::materialize_scoped(
            src,
            &resolved,
            Some(builder_sha),
            env.get("SOURCE_SUBMODULE_TOKEN")
                .map(String::as_str)
                .unwrap_or(""),
            website.as_ref(),
            &checkout,
        )?;
        Ok((resolved, predecessor))
    })();
    let cleanup_ok = fs::remove_file(&key).is_ok()
        && fs::remove_file(&known).is_ok()
        && (!website_key.exists() || fs::remove_file(&website_key).is_ok());
    if !cleanup_ok {
        return Err("Pre-release CI checkout credential cleanup failed");
    }
    result
}

fn strip_checkout_credentials(env: &Environment) -> Environment {
    let mut parent = env.clone();
    for name in [
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "SOURCE_SUBMODULE_TOKEN",
        "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
    ] {
        parent.remove(name);
    }
    parent
}

fn create_private_scratch(
    env: &Environment,
    prefix: &str,
) -> Result<(tempfile::TempDir, PathBuf, PathBuf)> {
    let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|_| "Pre-release CI runner directory unavailable")?;
    guards::directory(&runner)?;
    let scratch = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&runner)
        .map_err(|_| "Private pre-release CI workspace unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure pre-release CI workspace")?;
    }
    let root = scratch
        .path()
        .canonicalize()
        .map_err(|_| "Private pre-release CI workspace unavailable")?;
    let src = root.join("source");
    launch::directory(&src)?;
    Ok((scratch, root, src))
}

/// Resolve the exact `main` source SHA (or verified ancestor override),
/// compute the opaque `catalog_sha256` from the pinned source's own
/// `leap-release helper validation source-ci-catalog`, and output ONLY opaque
/// hashes (`source_sha`, `predecessor_sha`, `catalog_sha256`, `gate_fingerprint`).
pub fn resolve_nightly_source(env: &Environment) -> Result<()> {
    require_nightly_origin(env)?;
    audit_nightly_workflow()?;
    let requested = env
        .get("INPUT_SOURCE_SHA")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !requested.is_empty() && !valid_sha(&requested) {
        return Err("Invalid requested source SHA");
    }
    let builder_sha = required(env, "GITHUB_SHA")?.to_owned();
    let (_scratch, root, src) = create_private_scratch(env, "native-nightly-resolve-")?;
    let mut bootstrap = launch::private_file(&root.join("bootstrap.log"), b"")?;
    launch::private_file(&root.join("task.log"), b"")?;

    let result = (|| {
        println!("Native pre-release CI phase: private-checkout");
        let (source_sha, predecessor) =
            acquire_private_main_source(env, &root, &src, &requested, &builder_sha, true)?;
        let predecessor_sha =
            predecessor.ok_or("Predecessor commit missing for agent-lifecycle stage")?;
        let parent = strip_checkout_credentials(env);
        let (binary, build_env) =
            launch::build_release_cli(&src, &root, &parent, &source_sha, true, &mut bootstrap)?;
        let mut helper_env = clean_environment(&parent);
        for key in ["HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_HOME"] {
            if let Some(value) = build_env.get(key) {
                helper_env.insert(key.into(), value.clone());
            }
        }
        helper_env.insert(
            "LEAP_RELEASE_SOURCE_ROOT".into(),
            src.to_string_lossy().into_owned(),
        );
        println!("Native pre-release CI phase: catalog-digest");
        let output = process::run(
            &binary,
            &[
                "helper".into(),
                "validation".into(),
                "source-ci-catalog".into(),
                "--source-sha".into(),
                source_sha.clone(),
            ],
            &root,
            &helper_env,
            Duration::from_secs(300),
            None,
        )?;
        let summary = crate::json::parse(&output)?;
        let catalog_sha256 = summary["catalog_sha256"]
            .as_str()
            .filter(|v| source_api::hash(v))
            .ok_or("Invalid source-CI catalog digest")?
            .to_owned();
        let fingerprint = gate_fingerprint(&source_sha, &builder_sha, &catalog_sha256)?;
        launch::write_outputs(
            env,
            &[
                ("source_sha", &source_sha),
                ("predecessor_sha", &predecessor_sha),
                ("catalog_sha256", &catalog_sha256),
                ("gate_fingerprint", &fingerprint),
            ],
        )?;
        println!("Resolved nightly pre-release CI inputs (gate fingerprint: {fingerprint}).");
        Ok(())
    })();
    drop(bootstrap);
    if result.is_err() {
        eprintln!(
            "Checkout category: {}",
            launch::checkout_failure(&root.join("bootstrap.log"))
        );
        launch::seal(&root, env);
    }
    result
}

pub fn build_stage_request(env: &Environment) -> Result<(SourceCiRequest, String)> {
    require_nightly_origin(env)?;
    let stage = required(env, "PRE_RELEASE_CI_STAGE")?;
    if !CI_STAGES.contains(&stage) {
        return Err("Unsupported pre-release CI stage");
    }
    let source_sha = required(env, "RESOLVED_SOURCE_SHA")?;
    let catalog_sha256 = required(env, "SOURCE_CI_CATALOG_SHA256")?;
    if !valid_sha(source_sha) || !source_api::hash(catalog_sha256) {
        return Err("Invalid pre-release CI stage inputs");
    }
    let request = SourceCiRequest {
        identity: PipelineIdentity {
            source_repository: required(env, "SOURCE_REPOSITORY")?.into(),
            source_sha: source_sha.into(),
            builder_repository: BUILDER_REPOSITORY.into(),
            builder_sha: required(env, "GITHUB_SHA")?.into(),
            run_id: required(env, "GITHUB_RUN_ID")?.into(),
            attempt: required(env, "GITHUB_RUN_ATTEMPT")?.into(),
        },
        source_ref: "refs/heads/main".into(),
        stage: stage.into(),
        shard_index: 0,
        shard_count: 1,
    };
    SourceCiRequest::parse(&serde_json::to_value(&request).map_err(|_| "Invalid CI request")?)?;
    Ok((request, catalog_sha256.into()))
}

pub fn verify_nightly_stage_receipt(
    path: &Path,
    request: &SourceCiRequest,
    expected_catalog_sha256: &str,
) -> Result<Value> {
    if path.file_name().and_then(|p| p.to_str()) != Some("source-ci-stage.json") {
        return Err("Pre-release CI receipt filename mismatch");
    }
    guards::directory(
        path.parent()
            .ok_or("Pre-release CI receipt parent missing")?,
    )?;
    let mut file = guards::open_regular(path, source_api::MAX_RECEIPT as u64)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(source_api::MAX_RECEIPT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Pre-release CI receipt unreadable")?;
    if bytes.len() > source_api::MAX_RECEIPT {
        return Err("Pre-release CI receipt exceeds bound");
    }
    let receipt = crate::json::parse(&bytes)?;
    source_handoff::verify_stage_receipt_for_catalog(
        &receipt,
        request,
        expected_catalog_sha256,
        None,
    )
}

/// Execute one zero-leak stage of the 13-stage pre-release CI gate on the exact
/// resolved `source_sha`. Strips all checkout credentials and secrets before
/// running `leap-release ci`, verifies every test case passed with zero skips,
/// and seals encrypted failure diagnostics when any check fails.
pub fn run_pre_release_ci(env: &Environment) -> Result<()> {
    let (request, catalog_sha256) = build_stage_request(env)?;
    audit_nightly_workflow()?;
    let (_scratch, root, src) = create_private_scratch(env, "native-nightly-ci-")?;
    let mut bootstrap = launch::private_file(&root.join("bootstrap.log"), b"")?;
    launch::private_file(&root.join("task.log"), b"")?;

    let result = (|| {
        println!(
            "Native pre-release CI phase: private-checkout (stage={})",
            request.stage
        );
        let (acquired, _) = acquire_private_main_source(
            env,
            &root,
            &src,
            &request.identity.source_sha,
            &request.identity.builder_sha,
            false,
        )?;
        if acquired != request.identity.source_sha {
            return Err("Pre-release CI resolved SHA mismatch");
        }
        let mut parent = strip_checkout_credentials(env);
        parent.insert("SOURCE_CI_CATALOG_SHA256".into(), catalog_sha256.clone());
        if request.stage == "agent-lifecycle" {
            let predecessor = required(env, "LEAP_E2E_AGENT_PREDECESSOR_COMMIT")?;
            if !valid_sha(predecessor) || predecessor == request.identity.source_sha {
                return Err("Invalid pre-release agent predecessor SHA");
            }
            parent.insert(
                "LEAP_E2E_AGENT_PREDECESSOR_COMMIT".into(),
                predecessor.into(),
            );
        }
        launch::build_and_dispatch_ci(&src, &root, &parent, &request, &mut bootstrap)?;
        let summary = verify_nightly_stage_receipt(
            &root.join("release-work/source-ci-stage.json"),
            &request,
            &catalog_sha256,
        )?;
        let passed = summary["passed"].as_u64().unwrap_or(0);
        println!(
            "Pre-release CI stage '{}' passed ({passed} verified test cases, 0 failed, 0 skipped).",
            request.stage
        );
        Ok(())
    })();
    drop(bootstrap);
    if result.is_err() {
        eprintln!(
            "Checkout category: {}",
            launch::checkout_failure(&root.join("bootstrap.log"))
        );
        launch::seal(&root, env);
    }
    result
}

/// Upload encrypted failure diagnostics produced by `resolve-nightly-source` or
/// `pre-release-ci` into private storage (`STORAGE_CONFIG`) with zero plaintext
/// exposure.
pub fn retain_nightly_diagnostics(env: &Environment) -> Result<()> {
    require_nightly_origin(env)?;
    audit_nightly_workflow()?;
    let source_sha = required(env, "RESOLVED_SOURCE_SHA")?;
    if !valid_sha(source_sha) {
        return Err("Invalid resolved source SHA for diagnostic retention");
    }
    let scope = required(env, "RELEASE_ARTIFACT_SCOPE")?;
    if scope.is_empty()
        || scope.len() > 64
        || !scope.as_bytes()[0].is_ascii_lowercase()
        || !scope
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("Invalid nightly diagnostic scope");
    }
    required(env, "STORAGE_CONFIG")?;
    let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|_| "Runner temporary directory unavailable")?;
    guards::directory(&runner)?;
    let sealed = runner.join("encrypted-diagnostics/diagnostics.sealed");
    match fs::symlink_metadata(&sealed) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("No encrypted diagnostic produced by this job.");
            return Ok(());
        }
        Err(_) => return Err("Encrypted diagnostic unavailable"),
        Ok(_) => {}
    }
    for ancestor in sealed.ancestors().take_while(|p| *p != runner) {
        if guards::reparse(
            &fs::symlink_metadata(ancestor).map_err(|_| "Unsafe encrypted diagnostic path")?,
        ) {
            return Err("Unsafe encrypted diagnostic path");
        }
    }
    guards::open_regular(&sealed, 32 * 1024 * 1024)?;

    let builder_sha = required(env, "GITHUB_SHA")?.to_owned();
    let (_scratch, root, src) = create_private_scratch(env, "native-nightly-diag-")?;
    let mut bootstrap = launch::private_file(&root.join("bootstrap.log"), b"")?;
    launch::private_file(&root.join("task.log"), b"")?;

    let (acquired, _) =
        acquire_private_main_source(env, &root, &src, source_sha, &builder_sha, false)?;
    if acquired != source_sha {
        return Err("Diagnostic retention source SHA mismatch");
    }
    let parent = strip_checkout_credentials(env);
    let (binary, build_env) =
        launch::build_release_cli(&src, &root, &parent, source_sha, true, &mut bootstrap)?;
    let mut storage_env = clean_environment(&parent);
    for name in [
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "SOURCE_REPOSITORY",
        "SOURCE_BRANCH",
        "RESOLVED_SOURCE_SHA",
        "RUNNER_TEMP",
        "STORAGE_CONFIG",
    ] {
        storage_env.insert(name.into(), required(env, name)?.into());
    }
    for key in ["HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_HOME"] {
        if let Some(value) = build_env.get(key) {
            storage_env.insert(key.into(), value.clone());
        }
    }
    storage_env.insert("PUBLIC_BUILDER_SHA".into(), builder_sha);
    storage_env.insert(
        "LEAP_RELEASE_SOURCE_ROOT".into(),
        src.to_string_lossy().into_owned(),
    );
    storage_env.insert("RELEASE_STORAGE_KIND".into(), "nightly-ci".into());
    storage_env.insert("RELEASE_ARTIFACT_KIND".into(), "diagnostics".into());
    storage_env.insert("RELEASE_ARTIFACT_SCOPE".into(), scope.into());

    process::run(
        &binary,
        &[
            "helper".into(),
            "artifacts".into(),
            "retain-build-artifacts".into(),
            "--input".into(),
            sealed.to_string_lossy().into_owned(),
            "--kind".into(),
            "diagnostics".into(),
            "--scope".into(),
            scope.into(),
        ],
        &root,
        &storage_env,
        Duration::from_secs(600),
        Some(&mut bootstrap),
    )?;
    println!("Encrypted pre-release CI diagnostic retained privately.");
    Ok(())
}
