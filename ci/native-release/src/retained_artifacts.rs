//! The uploader reacquires and freezes the exact source before storage is scoped.
use crate::{
    Environment, Result, clean_environment, guards,
    input::{self, Request},
    process,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Artifact {
    pub path: PathBuf,
    pub kind: String,
    pub scope: String,
}
pub fn pipeline_kind(env: &Environment) -> Result<&'static str> {
    match env.get("GITHUB_WORKFLOW_REF").map(String::as_str) {
        Some("omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main") => {
            Ok("application")
        }
        Some(crate::agent::WORKFLOW_REF) => Ok("agent"),
        _ => Err("Untrusted private artifact workflow"),
    }
}

fn required<'a>(env: &'a Environment, key: &str) -> Result<&'a str> {
    env.get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or("Missing private artifact retention configuration")
}
pub fn ordinary(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().ok_or("Invalid native artifact path")?;
    Ok(PathBuf::from(text.strip_prefix("\\\\?\\").unwrap_or(text)))
}
fn runner(env: &Environment) -> Result<PathBuf> {
    let path = Path::new(required(env, "RUNNER_TEMP")?);
    if !path.is_absolute() {
        return Err("Invalid private artifact runner directory");
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Private artifact runner directory missing")?;
    if !metadata.is_dir() || guards::reparse(&metadata) {
        return Err("Invalid private artifact runner directory");
    }
    path.canonicalize()
        .map_err(|_| "Invalid private artifact runner directory")
}
pub fn artifact(env: &Environment, request: &Request) -> Result<Option<Artifact>> {
    let kind = required(env, "RELEASE_ARTIFACT_KIND")?;
    let scope = required(env, "RELEASE_ARTIFACT_SCOPE")?;
    if scope.len() > 64
        || !scope.as_bytes()[0].is_ascii_lowercase()
        || !scope
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("Invalid private artifact retention scope");
    }
    let pipeline = pipeline_kind(env)?;
    if pipeline == "agent" {
        let platform = required(env, "OMNI_AGENT_PLATFORM")?;
        crate::agent::target(platform)?;
        if scope != format!("agent-{}", platform.replace('_', "-")) {
            return Err("Agent artifact scope differs from its platform");
        }
    }
    if kind == "agent-packages" {
        if pipeline != "agent" || !request.build_only {
            return Err("Unauthorized native agent handoff retention");
        }
        let path = runner(env)?.join("agent-release");
        crate::agent::verify_handoff(
            &path,
            &request.version,
            required(env, "OMNI_AGENT_PLATFORM")?,
        )?;
        return Ok(Some(Artifact {
            path,
            kind: kind.into(),
            scope: scope.into(),
        }));
    }
    let (name, maximum) = match kind {
        "diagnostics" => ("encrypted-diagnostics/diagnostics.sealed", 32 * 1024 * 1024),
        "evaluation"
            if pipeline == "application"
                && request.build_only
                && request.preview_windows_self_sign
                && required(env, "RELEASE_TARGET")? == "windows"
                && scope == "verify-windows" =>
        {
            (
                "encrypted-evaluation/evaluation.sealed",
                512 * 1024 * 1024 + 32 * 1024,
            )
        }
        _ => return Err("Artifact retention differs from the authorized request"),
    };
    let runner = runner(env)?;
    let path = runner.join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && kind == "diagnostics" => {
            return Ok(None);
        }
        Err(_) => return Err("Requested encrypted artifact missing"),
        Ok(_) => {}
    }
    for ancestor in path.ancestors().take_while(|path| *path != runner) {
        if guards::reparse(
            &fs::symlink_metadata(ancestor).map_err(|_| "Unsafe private artifact path")?,
        ) {
            return Err("Unsafe private artifact path");
        }
    }
    guards::open_regular(&path, maximum)?;
    Ok(Some(Artifact {
        path,
        kind: kind.into(),
        scope: scope.into(),
    }))
}

fn identity(env: &Environment, source_sha: &str) -> Result<Value> {
    if pipeline_kind(env)? == "agent" {
        crate::agent::validate_authority(env)?;
    } else {
        input::validate_authority(env)?;
    }
    if !input::valid_sha(source_sha)
        || required(env, "RESOLVED_SOURCE_SHA")? != source_sha
        || env
            .get("PUBLIC_BUILDER_SHA")
            .is_some_and(|value| value != &env["GITHUB_SHA"])
    {
        return Err("Private artifact identity differs from acquired source or builder");
    }
    Ok(
        json!({"source_repository":env["SOURCE_REPOSITORY"], "source_sha":source_sha,
        "builder_repository":env["GITHUB_REPOSITORY"], "builder_sha":env["GITHUB_SHA"],
        "run_id":env["GITHUB_RUN_ID"], "attempt":env["GITHUB_RUN_ATTEMPT"]}),
    )
}

/// No signing, checkout, provider, workflow output, or recipient credential enters
/// either SDK transfer or ciphertext retention. Only the selected store can write.
pub fn storage_environment(
    env: &Environment,
    source: &Path,
    source_sha: &str,
) -> Result<Environment> {
    identity(env, source_sha)?;
    let mut safe = clean_environment(env);
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
        safe.insert(name.into(), required(env, name)?.into());
    }
    safe.insert("PUBLIC_BUILDER_SHA".into(), env["GITHUB_SHA"].clone());
    safe.insert(
        "OMNI_RELEASE_SOURCE_ROOT".into(),
        source.to_string_lossy().into_owned(),
    );
    safe.insert("RELEASE_STORAGE_KIND".into(), pipeline_kind(env)?.into());
    if pipeline_kind(env)? == "agent" {
        safe.insert(
            "OMNI_AGENT_PLATFORM".into(),
            required(env, "OMNI_AGENT_PLATFORM")?.into(),
        );
        safe.insert(
            "OMNI_AGENT_VERSION".into(),
            crate::agent::approved_source()?.version,
        );
    }
    Ok(safe)
}

pub fn preview_directory(env: &Environment) -> Result<PathBuf> {
    Ok(ordinary(&runner(env)?)?.join("windows-preview"))
}
/// Called after the successful build and a fresh source/tool freeze. The ZIP and
/// checksum are produced by the private Windows worker, then streamed as AES-GCM.
pub fn seal_evaluation(
    env: &Environment,
    request: &Request,
    work: &Path,
    log: &mut fs::File,
) -> Result<()> {
    if !request.build_only
        || !request.preview_windows_self_sign
        || required(env, "RELEASE_TARGET")? != "windows"
    {
        return Err("Unauthorized Windows evaluation producer");
    }
    let identity = identity(env, &request.source_sha)?;
    let runner = runner(env)?;
    let output_root = runner.join("encrypted-evaluation");
    fs::create_dir(&output_root).map_err(|_| "Evaluation encryption directory must be fresh")?;
    let identity_file = work.join("evaluation-identity.json");
    crate::launch::private_file(
        &identity_file,
        &serde_json::to_vec(&identity).map_err(|_| "Invalid evaluation identity")?,
    )?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Evaluation encryption tool missing")?
        .join("seal_evaluation.cjs");
    let input = preview_directory(env)?;
    let mut safe = clean_environment(env);
    safe.insert(
        "DIAGNOSTICS_PUBLIC_KEY".into(),
        required(env, "DIAGNOSTICS_PUBLIC_KEY")?.into(),
    );
    let outcome = process::run(
        Path::new("node"),
        &[
            ordinary(&script)?.to_string_lossy().into_owned(),
            input.to_string_lossy().into_owned(),
            ordinary(&output_root.join("evaluation.sealed"))?
                .to_string_lossy()
                .into_owned(),
            ordinary(&identity_file)?.to_string_lossy().into_owned(),
            "verify-windows".into(),
        ],
        work,
        &safe,
        Duration::from_secs(180),
        Some(log),
    );
    let _ = fs::remove_file(&identity_file);
    // Clean the owned plaintext pair even when recipient encryption fails.
    let cleanup = (|| {
        if let Ok(metadata) = fs::symlink_metadata(&input) {
            if !metadata.is_dir()
                || guards::reparse(&metadata)
                || ordinary(
                    &input
                        .canonicalize()
                        .map_err(|_| "Invalid evaluation plaintext directory")?,
                )? != input
            {
                return Err("Invalid evaluation plaintext directory");
            }
            fs::remove_dir_all(&input).map_err(|_| "Evaluation plaintext cleanup failed")?;
        }
        Ok(())
    })();
    outcome?;
    cleanup
}
