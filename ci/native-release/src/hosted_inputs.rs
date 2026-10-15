//! Materialize exact protected JSON in a job-owned directory. This establishes
//! input custody only; native preflight validates authority and actual services.
use crate::{Environment, Result, guards, launch};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn required<'a>(env: &'a Environment, name: &str) -> Result<&'a str> {
    env.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("Protected hosted input missing")
}

fn origin(env: &Environment) -> Result<()> {
    for (name, expected) in [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "omnisolo-llc/leapterm-release"),
        ("GITHUB_REF", "refs/heads/main"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main",
        ),
    ] {
        if env.get(name).map(String::as_str) != Some(expected) {
            return Err("Protected hosted input origin denied");
        }
    }
    if !env
        .get("GITHUB_SHA")
        .is_some_and(|value| crate::input::valid_sha(value))
    {
        return Err("Protected hosted input builder missing");
    }
    Ok(())
}

#[cfg(windows)]
enum OwnerCommand {
    Identity,
    Acl,
}

#[cfg(windows)]
fn native_system_directory() -> Result<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = [0u16; 4096];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Windows native system directory unavailable");
    }
    let root = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !root.is_absolute() {
        return Err("Windows native system directory unavailable");
    }
    guards::directory(&root)?;
    Ok(root)
}

#[cfg(windows)]
fn owner_command_failure(command: OwnerCommand, error: &'static str) -> &'static str {
    let category = match error {
        "Required build tool could not start" => "start",
        "Process-tree cleanup unavailable" => "group",
        "Suspended process cannot resume" => "resume",
        "Build command timed out" => "timeout",
        "Build output stream did not close" => "stream",
        "Build command failed; inspect private diagnostics" => "failed",
        _ => "other",
    };
    let (stage, message) = match command {
        OwnerCommand::Identity => (
            "windows-owner-command",
            "Windows hosted input owner command failed",
        ),
        OwnerCommand::Acl => (
            "windows-acl-command",
            "Windows hosted input ACL command failed",
        ),
    };
    eprintln!("Native hosted input command: {stage} {category}");
    message
}

fn owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let before = fs::symlink_metadata(path).map_err(|_| "Hosted input unavailable")?;
        if before.uid() != unsafe { libc::geteuid() } || guards::reparse(&before) {
            return Err("Hosted input owner changed");
        }
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if before.is_dir() { 0o700 } else { 0o600 }),
        )
        .map_err(|_| "Cannot secure hosted input")?;
    }
    #[cfg(windows)]
    {
        use std::time::Duration;
        let env = crate::clean_environment(&std::env::vars().collect());
        // Git Bash can put GNU whoami ahead of the native identity tool.
        // Select the OS directory through the API for both Windows commands.
        let system = native_system_directory()?;
        let bytes = crate::process::run(
            &system.join("whoami.exe"),
            &["/user".into(), "/fo".into(), "csv".into(), "/nh".into()],
            path.parent().ok_or("Hosted input parent unavailable")?,
            &env,
            Duration::from_secs(30),
            None,
        )
        .map_err(|error| owner_command_failure(OwnerCommand::Identity, error))?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "Hosted input owner unavailable")?;
        let sid = text
            .trim()
            .split(',')
            .nth(1)
            .ok_or("Hosted input owner unavailable")?
            .trim_matches('"');
        if !sid.starts_with("S-1-")
            || !sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
        {
            return Err("Hosted input owner invalid");
        }
        let grant = format!("*{sid}:{}", if path.is_dir() { "(OI)(CI)F" } else { "F" });
        crate::process::run(
            &system.join("icacls.exe"),
            &[
                path.to_string_lossy().into_owned(),
                "/inheritance:r".into(),
                "/grant:r".into(),
                grant,
            ],
            path.parent().ok_or("Hosted input parent unavailable")?,
            &env,
            Duration::from_secs(30),
            None,
        )
        .map_err(|error| owner_command_failure(OwnerCommand::Acl, error))?;
    }
    Ok(())
}

pub fn materialize(
    runner: &Path,
    prefix: &str,
    name: &str,
    raw: &str,
    expected_sha256: Option<&str>,
) -> Result<PathBuf> {
    let (temporary, file) = materialize_guarded(runner, prefix, name, raw, expected_sha256)?;
    let _retained = temporary.keep();
    Ok(file)
}

fn materialize_guarded(
    runner: &Path,
    prefix: &str,
    name: &str,
    raw: &str,
    expected_sha256: Option<&str>,
) -> Result<(tempfile::TempDir, PathBuf)> {
    if ![
        ("omni-installed-control-", "control.json"),
        ("omni-protected-source-pair-", "profile.json"),
    ]
    .contains(&(prefix, name))
    {
        return Err("Hosted input name denied");
    }
    if raw.is_empty() || raw.len() > 128 * 1024 {
        return Err("Protected hosted input bound");
    }
    let value = crate::json::parse(raw.as_bytes())?;
    if !value.is_object() {
        return Err("Protected hosted input must be an original JSON object");
    }
    if let Some(expected) = expected_sha256 {
        use sha2::{Digest, Sha256};
        if !crate::source_api::hash(expected)
            || format!("{:x}", Sha256::digest(raw.as_bytes())) != expected
        {
            return Err("Protected hosted input digest changed");
        }
    }
    guards::directory(runner)?;
    let temporary = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(runner)
        .map_err(|_| "Hosted input directory unavailable")?;
    let root = temporary
        .path()
        .canonicalize()
        .map_err(|_| "Hosted input directory unavailable")?;
    owner_only(&root)?;
    let file = root.join(name);
    launch::private_file(&file, raw.as_bytes())?;
    owner_only(&file)?;
    let held = guards::open_regular(&file, 128 * 1024)?;
    guards::single_link(&held)?;
    guards::unchanged(&held, &file)?;
    Ok((temporary, file))
}

pub fn run(command: &str, env: &Environment) -> Result<()> {
    origin(env)?;
    let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|_| "Hosted input runner unavailable")?;
    let platform = required(env, "LEAP_INTEGRATION_PLATFORM")?;
    if platform == "web" {
        return Ok(());
    }
    if !["linux", "macos", "windows", "android", "ios"].contains(&platform) {
        return Err("Hosted input platform denied");
    }
    let (input, prefix, name, output, pin) = match command {
        "prepare-installed-control" => (
            "LEAP_VPN_INSTALLED_CONTROL_JSON",
            "omni-installed-control-",
            "control.json",
            "control_file",
            None,
        ),
        "prepare-protected-source-pair" => (
            "LEAP_PROTECTED_DESKTOP_SOURCE_PROFILE_JSON",
            "omni-protected-source-pair-",
            "profile.json",
            "profile_file",
            Some(required(
                env,
                "LEAP_PROTECTED_DESKTOP_SOURCE_PROFILE_SHA256",
            )?),
        ),
        _ => return Err("Unknown protected hosted input command"),
    };
    let raw = required(env, input)?;
    let value = crate::json::parse(raw.as_bytes())?;
    if command == "prepare-installed-control" {
        crate::source_api::fields(&value, &["schema", "campaigns"])?;
        if value["schema"] != 1
            || value["campaigns"]
                .as_array()
                .is_none_or(|rows| rows.len() != 4)
        {
            return Err("Installed control original campaigns missing");
        }
    } else if (value["schema"] != "omniterm.protected-desktop.source-profile.v1"
        && value["schema"] != "omniterm.protected-desktop.source-profile.v2")
        || value["platform"] != platform
    {
        return Err("Protected source pair original profile missing");
    }
    let (temporary, file) = materialize_guarded(&runner, prefix, name, raw, pin)?;
    launch::write_outputs(
        env,
        &[(output, file.to_str().ok_or("Hosted input path encoding")?)],
    )?;
    let _retained = temporary.keep();
    Ok(())
}

pub fn cleanup(env: &Environment) -> Result<()> {
    origin(env)?;
    let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
        .canonicalize()
        .map_err(|_| "Hosted input runner unavailable")?;
    for (name, prefix, filename) in [
        (
            "LEAP_VPN_INSTALLED_CONTROL_FILE",
            "omni-installed-control-",
            "control.json",
        ),
        (
            "LEAP_PROTECTED_DESKTOP_SOURCE_PROFILE_FILE",
            "omni-protected-source-pair-",
            "profile.json",
        ),
    ] {
        if let Some(value) = env.get(name).filter(|value| !value.is_empty()) {
            let file = PathBuf::from(value);
            let root = file.parent().ok_or("Hosted input cleanup parent")?;
            if file.file_name().and_then(|value| value.to_str()) != Some(filename)
                || !file.is_absolute()
                || file
                    .canonicalize()
                    .map_err(|_| "Hosted input cleanup file unavailable")?
                    != file
                || root.parent() != Some(runner.as_path())
                || !root
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with(prefix))
            {
                return Err("Hosted input cleanup boundary");
            }
            guards::directory(root)?;
            guards::open_regular(&file, 128 * 1024)?;
            fs::remove_file(&file)
                .and_then(|_| fs::remove_dir(root))
                .map_err(|_| "Hosted input cleanup failed")?;
        }
    }
    Ok(())
}
