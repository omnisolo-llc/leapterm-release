//! Trusted source acquisition for the separate ordinary CI pipeline.
use crate::{
    Environment, Result,
    ci_request::{self, SourceCiRequest},
    guards, launch, source, source_discovery,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn request_from_environment(env: &Environment) -> Result<SourceCiRequest> {
    let request = SourceCiRequest::parse_bytes(
        env.get("SOURCE_CI_REQUEST")
            .ok_or("Source-CI request missing")?
            .as_bytes(),
    )?;
    if request.shard_index != 0
        || request.shard_count != 1
        || env.get("GITHUB_SHA") != Some(&request.identity.builder_sha)
        || env.get("GITHUB_RUN_ID") != Some(&request.identity.run_id)
        || env.get("GITHUB_RUN_ATTEMPT") != Some(&request.identity.attempt)
        || !env
            .get("INPUT_CATALOG_SHA256")
            .is_some_and(|value| crate::source_api::hash(value))
    {
        return Err("Source-CI workflow cell or catalog changed");
    }
    Ok(request)
}

fn required<'a>(env: &'a Environment, name: &str) -> Result<&'a str> {
    env.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Protected source-CI acquisition input missing")
}

pub fn run(env: &Environment) -> Result<()> {
    let request = request_from_environment(env)?;
    let builder_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| "Builder root unavailable")?;
    let policy = crate::json::parse(
        &fs::read(builder_root.join("ci/standard-runner-policy.json"))
            .map_err(|_| "Runner policy unavailable")?,
    )?;
    let audit = crate::runner_policy::audit_workflows(
        &builder_root.join(".github/workflows/source-ci.yml"),
        &policy,
    )?;
    if !audit["findings"].as_array().is_some_and(Vec::is_empty) {
        return Err("Public source-CI workflow policy refused");
    }
    let observed = source_discovery::fresh_ci_observation(env, &request)?;
    ci_request::authorize_ci(&request, &observed)?;
    if required(env, "SOURCE_REPOSITORY")? != ci_request::SOURCE_REPOSITORY {
        return Err("Source-CI acquisition repository changed");
    }
    let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|_| "Source-CI runner directory unavailable")?;
    guards::directory(&runner)?;
    let scratch = tempfile::Builder::new()
        .prefix("native-private-ci-")
        .tempdir_in(&runner)
        .map_err(|_| "Private source-CI workspace unavailable")?;
    let root = scratch
        .path()
        .canonicalize()
        .map_err(|_| "Private source-CI workspace unavailable")?;
    let src = root.join("source");
    fs::create_dir(&src).map_err(|_| "Private source-CI source directory unavailable")?;
    let key = root.join("identity");
    let known = root.join("known_hosts");
    let website_key = root.join("website-identity");
    let key_data = required(env, "SOURCE_DEPLOY_KEY")?;
    let hosts = required(env, "SOURCE_KNOWN_HOSTS")?;
    if key_data.len() > 32768
        || !key_data.trim_start().starts_with("-----BEGIN ")
        || !key_data.contains("PRIVATE KEY-----")
        || hosts.len() > 65536
    {
        return Err("Invalid source-CI checkout credential format");
    }
    launch::private_file(
        &key,
        format!("{}\n", key_data.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    launch::private_file(
        &known,
        format!("{}\n", hosts.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    let mut bootstrap = launch::private_file(&root.join("bootstrap.log"), b"")?;
    launch::private_file(&root.join("task.log"), b"")?;
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
        for args in [
            vec!["init".into(), "-q".into()],
            vec!["config".into(), "core.autocrlf".into(), "false".into()],
            vec![
                "remote".into(),
                "add".into(),
                "origin".into(),
                "ssh://git@ssh.github.com:443/omnisolo-llc/omniterm.git".into(),
            ],
        ] {
            source::git(&src, &args, &acquisition)?;
        }
        source::git(
            &src,
            &[
                "-c".into(),
                "protocol.ssh.allow=always".into(),
                "fetch".into(),
                "--quiet".into(),
                "--no-tags".into(),
                "origin".into(),
                "+refs/heads/main:refs/remotes/origin/base".into(),
                format!("+{}:refs/remotes/origin/reviewed", request.source_ref),
            ],
            &acquisition,
        )?;
        let acquired = source::git(
            &src,
            &[
                "rev-parse".into(),
                "--verify".into(),
                "refs/remotes/origin/reviewed".into(),
            ],
            &acquisition,
        )?;
        if String::from_utf8(acquired)
            .map_err(|_| "Source-CI ref metadata invalid")?
            .trim()
            != request.identity.source_sha
        {
            return Err("Source-CI approved head changed before checkout");
        }
        let base = observed["base_sha"]
            .as_str()
            .ok_or("Source-CI approved base missing")?;
        source::git(
            &src,
            &[
                "merge-base".into(),
                "--is-ancestor".into(),
                base.into(),
                request.identity.source_sha.clone(),
            ],
            &acquisition,
        )?;
        source::git(
            &src,
            &[
                "checkout".into(),
                "--quiet".into(),
                "--detach".into(),
                request.identity.source_sha.clone(),
            ],
            &acquisition,
        )?;
        let checkout = crate::clean_environment(env);
        source::materialize_scoped(
            &src,
            &request.identity.source_sha,
            Some(&request.identity.builder_sha),
            env.get("SOURCE_SUBMODULE_TOKEN")
                .map(String::as_str)
                .unwrap_or(""),
            website.as_ref(),
            &checkout,
        )?;
        fs::remove_file(&key)
            .and_then(|_| fs::remove_file(&known))
            .map_err(|_| "Source-CI checkout credential cleanup failed")?;
        if website_key.exists() {
            fs::remove_file(&website_key)
                .map_err(|_| "Source-CI checkout credential cleanup failed")?;
        }
        let current = source_discovery::fresh_ci_observation(env, &request)?;
        ci_request::authorize_ci(&request, &current)?;
        if current != observed {
            return Err("Source-CI approval or source changed during acquisition");
        }
        let mut parent = env.clone();
        for name in [
            "SOURCE_DEPLOY_KEY",
            "SOURCE_KNOWN_HOSTS",
            "SOURCE_SUBMODULE_TOKEN",
            "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
        ] {
            parent.remove(name);
        }
        parent.insert(
            "SOURCE_CI_CATALOG_SHA256".into(),
            required(env, "INPUT_CATALOG_SHA256")?.into(),
        );
        launch::build_and_dispatch_ci(&src, &root, &parent, &request, &mut bootstrap)?;
        crate::source_handoff::retain_stage(
            &parent,
            &request,
            &root.join("release-work/source-ci-stage.json"),
        )?;
        Ok(())
    })();
    drop(bootstrap);
    for file in [&key, &known, &website_key] {
        let _ = fs::remove_file(file);
    }
    result
}
