//! Cross-build only after the existing private source authority is verified.
use crate::{Environment, Result, clean_environment, guards, input, process, source};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::Duration};

pub fn build(src: &Path, env: &Environment, log: &mut fs::File) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Err("Windows SDK source production requires its reviewed Linux cross worker");
    }
    source::verify_tools(src, &clean_environment(env))?;
    let runner = env
        .get("RUNNER_TEMP")
        .ok_or("SDK runner directory missing")?;
    let runner = Path::new(runner)
        .canonicalize()
        .map_err(|_| "SDK runner directory invalid")?;
    let prefix = runner.join("windows-native-sdk");
    let cache = runner.join("windows-native-sdk-source");
    let recipe = src.join("scripts/release/prepare-freerdp-windows.mjs");
    let safe = clean_environment(env);
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| "4".into());
    let arguments = vec![
        recipe.to_string_lossy().into_owned(),
        "--prefix".into(),
        prefix.to_string_lossy().into_owned(),
        "--cache".into(),
        cache.to_string_lossy().into_owned(),
        "--jobs".into(),
        jobs,
    ];
    let mut verification = arguments.clone();
    verification.push("--verify-only".into());
    let manifest = prefix.join("windows-sdk-source-manifest.json");
    let cached_valid = manifest.is_file()
        && process::run(
            Path::new("node"),
            &verification,
            src,
            &safe,
            Duration::from_secs(300),
            Some(log),
        )
        .is_ok();
    if !cached_valid {
        if fs::symlink_metadata(&prefix).is_ok() {
            fs::remove_dir_all(&prefix)
                .map_err(|_| "Windows SDK stale cache directory could not be cleared")?;
        }
        process::run(
            Path::new("node"),
            &arguments,
            src,
            &safe,
            Duration::from_secs(3600),
            Some(log),
        )?;
        process::run(
            Path::new("node"),
            &verification,
            src,
            &safe,
            Duration::from_secs(300),
            Some(log),
        )?;
    }
    let mut file = guards::open_regular(&manifest, 8 * 1024 * 1024)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "Windows SDK source manifest unreadable")?;
    let value = crate::json::parse(&bytes)?;
    if value["target"] != "x86_64-pc-windows-gnu"
        || value["verification"]["complete_windows_target_build"] != true
        || value["verification"]["imports_closed"] != true
    {
        return Err("Incomplete Windows SDK source producer output");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let source_sha = env
        .get("RESOLVED_SOURCE_SHA")
        .ok_or("SDK source revision missing")?;
    if !input::valid_sha(source_sha) {
        return Err("Invalid Windows SDK source revision");
    }
    Ok(digest)
}
