use crate::{
    Environment, Result, clean_environment,
    input::{Request, validate_authority},
    process, source,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
pub fn checkout_failure(path: &Path) -> &'static str {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = crate::guards::open_regular(path, 64 * 1024 * 1024) else {
        return "unclassified";
    };
    let Ok(info) = file.metadata() else {
        return "unclassified";
    };
    if file
        .seek(SeekFrom::Start(info.len().saturating_sub(65536)))
        .is_err()
    {
        return "unclassified";
    }
    let mut bytes = Vec::new();
    if file.take(65536).read_to_end(&mut bytes).is_err() {
        return "unclassified";
    }
    let text = String::from_utf8_lossy(&bytes);
    for (category, patterns) in [
        (
            "host-key-verification",
            vec!["Host key verification failed", "host key is known"],
        ),
        (
            "checkout-key-format",
            vec!["invalid format", "error in libcrypto"],
        ),
        (
            "checkout-authentication",
            vec!["Permission denied (publickey)", "Repository not found"],
        ),
        (
            "checkout-network",
            vec![
                "Could not resolve hostname",
                "Connection timed out",
                "Connection refused",
            ],
        ),
        (
            "source-reference",
            vec!["couldn't find remote ref", "Not a valid object name"],
        ),
    ] {
        if patterns.iter().any(|p| text.contains(p)) {
            return category;
        }
    }
    "unclassified"
}
pub fn diagnostic_phase(path: &Path) -> String {
    use std::io::Read;
    let Ok(mut file) = crate::guards::open_regular(path, 512) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let Ok(value) = crate::json::parse(&bytes) else {
        return String::new();
    };
    let stage = value["stage"].as_str().unwrap_or("");
    if ![
        "source-check",
        "rust-toolchain",
        "flutter-sdk",
        "system-dependencies",
        "android-sdk",
        "package-resolution",
        "application-build",
        "lockfile-check",
        "complete",
    ]
    .contains(&stage)
    {
        return String::new();
    }
    let mut result = format!("Last completed/attempted phase: {stage}\n");
    if let Some(categories) = value["diagnostics"].as_array() {
        for category in categories
            .iter()
            .take(6)
            .filter_map(serde_json::Value::as_str)
        {
            if [
                "android-kotlin-plugin",
                "android-sdk-level",
                "android-java-version",
                "android-namespace",
                "android-apk-output",
                "dependency-resolution",
                "windows-visual-studio",
                "cmake-minimum-version",
                "native-build-hook",
                "rust-compilation",
                "native-linker",
                "dart-compilation",
                "windows-symlinks",
                "missing-native-library",
                "network-download",
                "android-ndk",
            ]
            .contains(&category)
            {
                result.push_str(&format!("Build diagnostic category: {category}\n"));
            }
        }
    }
    result
}
fn required<'a>(env: &'a Environment, key: &str) -> Result<&'a str> {
    env.get(key)
        .filter(|v| !v.is_empty())
        .map(String::as_str)
        .ok_or("Missing protected native release configuration")
}
/// Protected configuration is scoped by workflow steps. Only named protocol inputs cross.
pub fn task_environment(parent: &Environment) -> Environment {
    let mut env = clean_environment(parent);
    for (key, value) in parent {
        if matches!(
            key.as_str(),
            "RELEASE_TARGET"
                | "RELEASE_REQUEST"
                | "SOURCE"
                | "SOURCE_REPOSITORY"
                | "SOURCE_BRANCH"
                | "RESOLVED_SOURCE_SHA"
                | "RESOLVED_VERSION"
                | "RESOLVED_BUILD_NUMBER"
                | "BUILD_CONFIG"
                | "STORAGE_CONFIG"
                | "SIGNING_CONFIG"
                | "DOWNLOAD_CONFIG"
                | "APPLE_CONFIG"
                | "RELEASE_CONFIG"
                | "GH_TOKEN"
                | "GITHUB_TOKEN"
                | "ACTIONS_ID_TOKEN_REQUEST_URL"
                | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        ) || (key.starts_with("GITHUB_")
            && ![
                "GITHUB_ENV",
                "GITHUB_OUTPUT",
                "GITHUB_PATH",
                "GITHUB_STATE",
                "GITHUB_STEP_SUMMARY",
            ]
            .contains(&key.as_str()))
            || key.starts_with("LEAP_")
            || key.starts_with("LEAPTERM_")
            || key.starts_with("APP_STORE_CONNECT_")
            || key.starts_with("RESOLVED_")
            || matches!(
                key.as_str(),
                "RUNNER_TEMP"
                    | "RELEASE_IOS_DELIVERY_RESULT"
                    | "PRIVATE_RELEASE_TOKEN"
                    | "WINDOWS_PREVIEW_OUTPUT_DIR"
                    | "MANAGED_RTC_PROVIDER_ENVIRONMENT_FILE"
                    | "MANAGED_RTC_IDENTITY_FIXTURE_FILE"
            )
        {
            env.insert(key.clone(), value.clone());
        }
    }
    env
}
/// Match the private application context's public trust-key contract before
/// acquiring source or compiling tools. This checks encoding, not provenance;
/// only the operator's reviewed provider key is valid for a real application.
fn validate_provider_public_key(env: &Environment) -> Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let encoded = env
        .get("LEAPTERM_VPN_PROVIDER_PUBLIC_KEY")
        .filter(|value| !value.is_empty())
        .ok_or("Missing LEAPTERM_VPN_PROVIDER_PUBLIC_KEY; configure the reviewed application trust key")?;
    const INVALID: &str = "Invalid LEAPTERM_VPN_PROVIDER_PUBLIC_KEY; expected a canonical nonzero 32-byte base64url public key";
    if encoded.len() != 43 {
        return Err(INVALID);
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| INVALID)?;
    if bytes.len() != 32
        || bytes.iter().all(|byte| *byte == 0)
        || URL_SAFE_NO_PAD.encode(&bytes) != *encoded
    {
        return Err(INVALID);
    }
    Ok(())
}

pub fn validate_configuration(env: &Environment, command: &str) -> Result<Request> {
    if command == "agent-run"
        || (command == "retain-artifacts"
            && env.get("GITHUB_WORKFLOW_REF").map(String::as_str)
                == Some(crate::agent::WORKFLOW_REF))
    {
        crate::agent::validate_authority(env)?;
    } else {
        validate_authority(env)?;
    }
    let target = required(env, "RELEASE_TARGET")?;
    if (command == "resolve" && target != "resolve")
        || (command == "verify-ios" && target != "ios")
        || (command == "windows-sdk" && target != "windows")
        || (command == "verify-build" && !crate::input::BUILD_TARGETS.contains(&target))
        || (command == "prepare-publication" && target != "publish")
        || (crate::private_final_archive::command(command) && target != "publish")
        || (command == "sign-public-candidates" && target != "publish")
        || (command == "run" && target == "resolve")
    {
        return Err("Native workflow target mismatch");
    }
    let mut request = Request::parse(required(env, "RELEASE_REQUEST")?)?;
    request.validate_target(target)?;
    if command == "verify-ios" && (!request.build_only || request.ios_action != "skip") {
        return Err("verify-ios requires unsigned build-only request");
    }
    if command != "agent-run" && request.builder_sha.is_empty() {
        request.builder_sha = required(env, "GITHUB_SHA")?.to_owned();
    }
    request.resolve_from(env)?;
    if !request.build_only {
        if request.builder_sha != required(env, "GITHUB_SHA")? {
            return Err("Requested builder differs from workflow revision");
        }
        // GitHub's enforced execution policy authorizes the operator. The
        // resolver freezes main (or an explicit ancestor) once for every job.
        if target != "resolve" && required(env, "RESOLVED_SOURCE_SHA")? != request.source_sha {
            return Err("Full release source differs from resolver");
        }
        if target != "resolve" && !["windows-sdk", "retain-artifacts"].contains(&command) {
            let config = crate::json::parse(required(env, "BUILD_CONFIG")?.as_bytes())?;
            if config
                .get("LEAP_ENABLE_VPN")
                .and_then(serde_json::Value::as_str)
                != Some("true")
            {
                return Err("Full releases require LEAP_ENABLE_VPN=true");
            }
            required(env, "STORAGE_CONFIG")?;
        }
    }
    if target != "resolve" && request.source_sha.is_empty() {
        return Err("Source revision must be resolved before building");
    }
    if !request.builder_sha.is_empty() && request.builder_sha != required(env, "GITHUB_SHA")? {
        return Err("Requested builder does not match workflow revision");
    }
    if !["agent-run", "windows-sdk", "retain-artifacts"].contains(&command) && target != "resolve" {
        validate_provider_public_key(env)?;
    }
    required(env, "SOURCE_DEPLOY_KEY")?;
    required(env, "SOURCE_KNOWN_HOSTS")?;
    if ["windows-sdk", "retain-artifacts"].contains(&command) {
        required(env, "STORAGE_CONFIG")?;
    }
    Ok(request)
}
pub fn write_outputs(env: &Environment, values: &[(&str, &str)]) -> Result<()> {
    let path = Path::new(required(env, "GITHUB_OUTPUT")?);
    let before = fs::symlink_metadata(path).map_err(|_| "Workflow output unavailable")?;
    if !before.is_file() || crate::guards::reparse(&before) {
        return Err("Unsafe workflow output");
    }
    let mut options = fs::OpenOptions::new();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        if before.nlink() != 1 {
            return Err("Unsafe workflow output");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Workflow output unavailable")?;
    crate::guards::single_link(&file)?;
    if !crate::guards::same(
        &before,
        &file.metadata().map_err(|_| "Workflow output unavailable")?,
    ) {
        return Err("Workflow output changed");
    }
    crate::guards::unchanged(&file, path)?;
    for (key, value) in values {
        if !key
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || *b == b'_')
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || value.contains(['\r', '\n', '\0'])
        {
            return Err("Unsafe workflow output value");
        }
    }
    for (key, value) in values {
        writeln!(file, "{key}={value}").map_err(|_| "Workflow output write failed")?;
    }
    Ok(())
}
pub fn git_ssh_candidates(git: &Path) -> Vec<PathBuf> {
    git.ancestors()
        .skip(1)
        .map(|p| p.join("usr/bin/ssh.exe"))
        .collect()
}
pub fn ssh_executable(env: &Environment) -> Result<PathBuf> {
    if cfg!(windows) {
        for base in std::env::split_paths(required(env, "PATH")?) {
            let git = base.join("git.exe");
            if git.is_file() {
                for path in git_ssh_candidates(&git) {
                    if path.is_file() {
                        return Ok(path);
                    }
                }
            }
        }
        Err("Git SSH is unavailable")
    } else {
        Ok(PathBuf::from("/usr/bin/ssh"))
    }
}
pub fn checkout_environment(env: &Environment, key: &Path, known: &Path) -> Result<Environment> {
    let mut safe = clean_environment(env);
    let ssh = ssh_executable(env)?;
    let ssh_null = if cfg!(windows) {
        "none"
    } else {
        crate::null_device()
    };
    safe.insert("GIT_SSH_COMMAND".into(),format!("{} -F {} -i {} -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={} -o GlobalKnownHostsFile={} -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ForwardAgent=no -o ClearAllForwardings=yes -o ConnectTimeout=30",quote(&ssh.to_string_lossy().replace('\\',"/")),ssh_null,quote(&key.to_string_lossy().replace('\\',"/")),quote(&known.to_string_lossy().replace('\\',"/")),ssh_null));
    safe.insert("GIT_SSH_VARIANT".into(), "ssh".into());
    Ok(safe)
}
pub fn decode_submodule_key(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    if value.len() > 65536 {
        return Err("Submodule key exceeds bound");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "Invalid submodule key encoding")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid submodule key format")?;
    if bytes.len() > 32768
        || !text.trim_start().starts_with("-----BEGIN ")
        || !text.contains("PRIVATE KEY-----")
    {
        return Err("Invalid submodule key format");
    }
    Ok(format!("{}\n", text.replace("\r\n", "\n").trim()).into_bytes())
}
pub(crate) fn private_file(path: &Path, bytes: &[u8]) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Cannot create private release file")?;
    file.write_all(bytes)
        .map_err(|_| "Cannot write private release file")?;
    Ok(file)
}
fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(|_| "Cannot create private release directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot secure release directory")?;
    }
    Ok(())
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn git_args(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn utf8(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| "Invalid native tool output")
}
fn seal(temp: &Path, env: &Environment) {
    let Some(recipient) = env.get("DIAGNOSTICS_PUBLIC_KEY").filter(|v| !v.is_empty()) else {
        return;
    };
    let Some(runner) = env.get("RUNNER_TEMP") else {
        return;
    };
    let mut safe = clean_environment(env);
    safe.insert("DIAGNOSTICS_PUBLIC_KEY".into(), recipient.clone());
    let sealer = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."))
        .join("seal_diagnostics.cjs");
    let target = Path::new(runner).join("encrypted-diagnostics/diagnostics.sealed");
    let args = vec![
        sealer.to_string_lossy().into_owned(),
        temp.to_string_lossy().into_owned(),
        target.to_string_lossy().into_owned(),
    ];
    if process::run(
        Path::new("node"),
        &args,
        temp,
        &safe,
        Duration::from_secs(30),
        None,
    )
    .is_err()
    {
        eprintln!("Encrypted native diagnostics could not be retained.");
    }
}

fn strip_verbatim(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

pub fn run(command: &str) -> Result<()> {
    let mut env: Environment = std::env::vars().collect();
    if command == "publish-candidates" {
        if std::env::args().len() != 2 {
            return Err("Unexpected native publication arguments");
        }
        let plan = crate::private_final_archive::require_publication(&env)?;
        let directory = crate::publication_candidates::directory(&env)?;
        let mut github = crate::publication_candidates::GitHub::new_for_repo(
            &env,
            &directory,
            plan.source_repository(),
        )?;
        crate::publication_candidates::publish_to_staging(&plan, &mut github)?;
        println!("Verified private staging release publication completed.");
        return Ok(());
    }
    if command == "validate-request" {
        if std::env::args().len() != 2 {
            return Err("Unexpected native release arguments");
        }
        validate_authority(&env)?;
        let request = Request::parse(required(&env, "RELEASE_REQUEST")?)?;
        let builder = required(&env, "GITHUB_SHA")?;
        if !request.builder_sha.is_empty() && request.builder_sha != builder {
            return Err("Requested builder differs from workflow revision");
        }
        // No source credentials are used here. Empty source selects main in
        // the subsequent resolver; supplied SHAs retain ancestry validation.
        write_outputs(
            &env,
            &[
                ("source_sha", &request.source_sha),
                ("builder_sha", builder),
            ],
        )?;
        return Ok(());
    }
    if command == "approve-source" || command == "agent-source" {
        if std::env::args().len() != 2 {
            return Err("Unexpected native release arguments");
        }
        if command == "approve-source" {
            let source = required(&env, "REQUESTED_SOURCE_SHA")?.to_ascii_lowercase();
            let builder = required(&env, "REQUESTED_BUILDER_SHA")?;
            crate::input::validate_approval(&env, &source, builder)?;
            write_outputs(&env, &[("source_sha", &source), ("builder_sha", builder)])?;
        } else {
            let pin = crate::agent::approved_source()?;
            write_outputs(
                &env,
                &[
                    ("source_sha", &pin.source_sha),
                    ("source_branch", &pin.source_branch),
                    ("version", &pin.version),
                ],
            )?;
        }
        return Ok(());
    }
    if command == "verify-agent-handoff" {
        let mut values = Environment::new();
        let mut args = std::env::args().skip(2);
        while let Some(key) = args.next() {
            if !["--directory", "--version", "--platform"].contains(&key.as_str())
                || values.contains_key(&key)
            {
                return Err("Invalid handoff arguments");
            }
            values.insert(key, args.next().ok_or("Missing handoff argument")?);
        }
        if values.len() != 3 {
            return Err("Missing handoff arguments");
        }
        let count = crate::agent::verify_handoff(
            Path::new(&values["--directory"]),
            &values["--version"],
            &values["--platform"],
        )?;
        println!(
            "Verified {count} native package hashes; signing and installation remain separate gates."
        );
        return Ok(());
    }
    if command == "verify-source" {
        let mut args = std::env::args().skip(2);
        let mut values = Environment::new();
        while let Some(key) = args.next() {
            if !["--root", "--sha"].contains(&key.as_str()) || values.contains_key(&key) {
                return Err("Invalid verification arguments");
            }
            let value = args.next().ok_or("Missing verification value")?;
            values.insert(key, value);
        }
        if values.len() != 2 {
            return Err("Expected --root and --sha");
        }
        source::verify_source(Path::new(&values["--root"]), &values["--sha"])?;
        println!("Verified unchanged native source tree.");
        return Ok(());
    }
    if ![
        "resolve",
        "verify-ios",
        "run",
        "verify-build",
        "prepare-publication",
        "prepare-private-final-archive",
        "verify-private-final-archive",
        "sign-public-candidates",
        "agent-run",
        "windows-sdk",
        "retain-artifacts",
    ]
    .contains(&command)
    {
        return Err("Unsupported native command; no legacy fallback");
    }
    if std::env::args().len() != 2 {
        return Err("Unexpected native release arguments");
    }
    let mut request = validate_configuration(&env, command)?;
    if crate::private_final_archive::command(command) {
        crate::publication_candidates::verify_prepared(&env)?;
    }
    let retained = if command == "retain-artifacts" {
        let Some(artifact) = crate::retained_artifacts::artifact(&env, &request)? else {
            println!("No encrypted diagnostic produced by this job.");
            return Ok(());
        };
        Some(artifact)
    } else {
        None
    };
    if command == "verify-ios" && !cfg!(target_os = "macos") {
        return Err("Native iOS verification requires macOS");
    }
    let builder = required(&env, "GITHUB_SHA")?.to_owned();
    let key_data = required(&env, "SOURCE_DEPLOY_KEY")?;
    let hosts = required(&env, "SOURCE_KNOWN_HOSTS")?;
    if key_data.len() > 32768
        || !key_data.trim_start().starts_with("-----BEGIN ")
        || !key_data.contains("PRIVATE KEY-----")
        || hosts.len() > 65536
    {
        return Err("Invalid checkout credential format");
    }

    let runner = strip_verbatim(
        PathBuf::from(required(&env, "RUNNER_TEMP")?)
            .canonicalize()
            .map_err(|_| "Runner temporary directory missing")?,
    );
    let temp = tempfile::Builder::new()
        .prefix("native-private-task-")
        .tempdir_in(&runner)
        .map_err(|_| "Private temporary directory unavailable")?;
    let root = strip_verbatim(
        temp.path()
            .canonicalize()
            .map_err(|_| "Private temporary directory unavailable")?,
    );
    let key = root.join("identity");
    let known = root.join("known_hosts");
    let website_key = root.join("website-identity");
    let src = root.join("source");
    directory(&src)?;
    let mut bootstrap = private_file(&root.join("bootstrap.log"), b"")?;
    let _ = private_file(&root.join("task.log"), b"")?;
    private_file(
        &key,
        format!("{}\n", key_data.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    private_file(
        &known,
        format!("{}\n", hosts.replace("\r\n", "\n").trim()).as_bytes(),
    )?;
    let result = (|| {
        let mut acquisition = checkout_environment(&env, &key, &known)?;
        acquisition.insert(
            "NATIVE_GIT_LOG".into(),
            root.join("bootstrap.log").to_string_lossy().into_owned(),
        );
        let website = env
            .get("SOURCE_SUBMODULE_DEPLOY_KEY_BASE64")
            .filter(|s| !s.is_empty())
            .map(|value| -> Result<Environment> {
                private_file(&website_key, &decode_submodule_key(value)?)?;
                checkout_environment(&env, &website_key, &known)
            })
            .transpose()?;
        source::git(&src, &git_args(&["init", "-q"]), &acquisition)?;
        source::git(
            &src,
            &git_args(&["config", "core.autocrlf", "false"]),
            &acquisition,
        )?;
        let origin_url = format!(
            "ssh://git@ssh.github.com:443/{}.git",
            required(&env, "SOURCE_REPOSITORY")?
        );
        source::git(
            &src,
            &git_args(&["remote", "add", "origin", &origin_url]),
            &acquisition,
        )?;
        println!("Native release phase: private-checkout");
        source::git(
            &src,
            &git_args(&[
                "-c",
                "protocol.ssh.allow=always",
                "fetch",
                "--quiet",
                "--no-tags",
                "origin",
                &format!(
                    "+refs/heads/{}:refs/remotes/origin/reviewed",
                    required(&env, "SOURCE_BRANCH")?
                ),
            ]),
            &acquisition,
        )?;
        request.source_sha = source::resolve_revision(&src, &request.source_sha, &acquisition)?;
        if command == "resolve" {
            let timestamp = utf8(process::run(
                Path::new("date"),
                &git_args(&["-u", "+%Y%m%d%H%M"]),
                &root,
                &clean_environment(&env),
                Duration::from_secs(15),
                None,
            )?)?
            .trim()
            .to_owned();
            if timestamp.len() != 12 || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Invalid workflow timestamp");
            }
            write_outputs(
                &env,
                &[
                    ("source_sha", &request.source_sha),
                    ("version", &request.version),
                    ("build_number", &request.build_number),
                    ("workflow_id", &timestamp),
                ],
            )?;
            println!("Native release inputs resolved.");
            return Ok(());
        }
        // Capture the acquired immutable revision before any native child starts.
        env.insert("RESOLVED_SOURCE_SHA".into(), request.source_sha.clone());
        source::git(
            &src,
            &git_args(&["checkout", "--quiet", "--detach", &request.source_sha]),
            &acquisition,
        )?;
        println!("Native release phase: source-check");
        let checkout = clean_environment(&env);
        source::materialize_scoped(
            &src,
            &request.source_sha,
            if command == "agent-run"
                || (command == "retain-artifacts"
                    && crate::retained_artifacts::pipeline_kind(&env)? == "agent")
            {
                None
            } else {
                Some(builder.as_str())
            },
            env.get("SOURCE_SUBMODULE_TOKEN")
                .map(String::as_str)
                .unwrap_or(""),
            website.as_ref(),
            &checkout,
        )?;
        fs::remove_file(&key)
            .and_then(|_| fs::remove_file(&known))
            .map_err(|_| "Checkout credential cleanup failed")?;
        if website_key.exists() {
            fs::remove_file(&website_key).map_err(|_| "Checkout credential cleanup failed")?;
        }
        for key in [
            "SOURCE_DEPLOY_KEY",
            "SOURCE_KNOWN_HOSTS",
            "SOURCE_SUBMODULE_TOKEN",
            "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
        ] {
            env.remove(key);
        }
        {
            use std::io::{Seek, SeekFrom};
            bootstrap
                .seek(SeekFrom::End(0))
                .map_err(|_| "Private build log unavailable")?;
        }
        if command == "windows-sdk" {
            let digest = crate::windows_sdk::build(&src, &env, &mut bootstrap)?;
            env.insert(
                "LEAPTERM_WINDOWS_SDK_MANIFEST_SHA256".into(),
                digest.clone(),
            );
            build_native_stage(
                &src,
                &root,
                &env,
                NativeStage::WindowsSdk(&request, "put"),
                &mut bootstrap,
            )?;
            write_outputs(
                &env,
                &[
                    ("manifest_sha256", &digest),
                    ("source_sha", &request.source_sha),
                ],
            )?;
        } else if command == "retain-artifacts" {
            build_native_stage(
                &src,
                &root,
                &env,
                NativeStage::RetainedArtifacts(
                    &request,
                    retained.as_ref().ok_or("Encrypted artifact missing")?,
                ),
                &mut bootstrap,
            )?;
        } else {
            build_and_dispatch(&src, &root, &env, &request, command, &mut bootstrap)?;
        }
        println!("Native release task completed.");
        Ok(())
    })();
    drop(bootstrap);
    let _ = fs::remove_file(&key);
    let _ = fs::remove_file(&known);
    let _ = fs::remove_file(&website_key);
    if result.is_err() {
        eprintln!(
            "Checkout category: {}",
            checkout_failure(&root.join("bootstrap.log"))
        );
        eprint!("{}", diagnostic_phase(&root.join("status.json")));
    }
    if command != "retain-artifacts" && (result.is_err() || command != "resolve") {
        seal(&root, &env);
    }
    result
}
/// Called only after acquisition, ancestry and complete source closure verification.
pub fn build_and_dispatch(
    src: &Path,
    root: &Path,
    env: &Environment,
    request: &Request,
    command: &str,
    bootstrap: &mut fs::File,
) -> Result<()> {
    build_native_stage(
        src,
        root,
        env,
        NativeStage::Release(request, command),
        bootstrap,
    )
}

/// The caller must establish fresh CI authority and acquire the exact source
/// before entering this common byte-checked native compilation boundary.
pub fn build_and_dispatch_ci(
    src: &Path,
    root: &Path,
    env: &Environment,
    request: &crate::ci_request::SourceCiRequest,
    bootstrap: &mut fs::File,
) -> Result<()> {
    crate::ci_request::SourceCiRequest::parse(
        &serde_json::to_value(request).map_err(|_| "Invalid CI request encoding")?,
    )?;
    if request.identity.builder_sha != required(env, "GITHUB_SHA")? {
        return Err("CI builder differs from executing revision");
    }
    build_native_stage(src, root, env, NativeStage::Ci(request), bootstrap)
}

enum NativeStage<'a> {
    Release(&'a Request, &'a str),
    Ci(&'a crate::ci_request::SourceCiRequest),
    WindowsSdk(&'a Request, &'a str),
    RetainedArtifacts(&'a Request, &'a crate::retained_artifacts::Artifact),
}
fn build_native_stage(
    src: &Path,
    root: &Path,
    env: &Environment,
    stage: NativeStage<'_>,
    bootstrap: &mut fs::File,
) -> Result<()> {
    let source_sha = match &stage {
        NativeStage::Release(request, _) => request.source_sha.as_str(),
        NativeStage::Ci(request) => request.identity.source_sha.as_str(),
        NativeStage::WindowsSdk(request, _) => request.source_sha.as_str(),
        NativeStage::RetainedArtifacts(request, _) => request.source_sha.as_str(),
    };
    for name in ["identity", "known_hosts", "website-identity"] {
        if root.join(name).exists() {
            return Err("Checkout credential cleanup failed");
        }
    }
    let checkout = clean_environment(env);
    source::verify(src, source_sha, &checkout, false, 0)?;
    source::verify_tools(src, &checkout)?;
    let frozen = crate::guards::Frozen::tree(&src.join("tools"), false)?;
    frozen.verify()?;
    source::verify(src, source_sha, &checkout, false, 0)?;
    source::verify_tools(src, &checkout)?;
    let mut build = clean_environment(env);
    let rustup = env
        .get("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env.get("HOME").map(String::as_str).unwrap_or("")).join(".rustup")
        });
    if !rustup.is_absolute() {
        return Err("Rust toolchain location unavailable");
    }
    for (name, part) in [
        ("HOME", "build-home"),
        ("CARGO_HOME", "cargo-home"),
        ("CARGO_TARGET_DIR", "native-target"),
    ] {
        let location = root.join(part);
        directory(&location)?;
        build.insert(name.into(), location.to_string_lossy().into_owned());
    }
    build.insert("RUSTUP_HOME".into(), rustup.to_string_lossy().into_owned());
    let cargo_jobs = env
        .get("CARGO_BUILD_JOBS")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| (1..=64).contains(&n))
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 64))
                .unwrap_or(2)
        })
        .to_string();
    build.insert("CARGO_BUILD_JOBS".into(), cargo_jobs);
    let manifest = src.join("tools/release-cli/Cargo.toml");
    if !manifest.is_file() || !src.join("tools/release-cli/Cargo.lock").is_file() {
        return Err("Pinned source does not contain native release tooling");
    }
    println!("Native release phase: native-toolchain");
    process::run(
        Path::new("rustup"),
        &git_args(&[
            "toolchain",
            "install",
            "1.95.0",
            "--profile",
            "minimal",
            "--no-self-update",
        ]),
        root,
        &build,
        Duration::from_secs(900),
        Some(bootstrap),
    )?;
    if !matches!(stage, NativeStage::RetainedArtifacts(_, _)) {
        println!("Native release phase: native-tool-tests");
        process::run(
            Path::new("cargo"),
            &[
                "+1.95.0".into(),
                "test".into(),
                "--locked".into(),
                "--manifest-path".into(),
                manifest.to_string_lossy().into_owned(),
            ],
            root,
            &build,
            Duration::from_secs(1800),
            Some(bootstrap),
        )?;
    }
    println!("Native release phase: native-tool-build");
    process::run(
        Path::new("cargo"),
        &[
            "+1.95.0".into(),
            "build".into(),
            "--locked".into(),
            "--release".into(),
            "--manifest-path".into(),
            manifest.to_string_lossy().into_owned(),
        ],
        root,
        &build,
        Duration::from_secs(1800),
        Some(bootstrap),
    )?;
    frozen.verify()?;
    source::verify_tools(src, &checkout)?;
    source::verify(src, source_sha, &checkout, false, 0)?;
    let work = root.join("release-work");
    directory(&work)?;
    let binary = root.join(if cfg!(windows) {
        "native-target/release/leap-release.exe"
    } else {
        "native-target/release/leap-release"
    });
    if !fs::symlink_metadata(&binary).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
        return Err("Native release executable missing");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::symlink_metadata(&binary)
            && meta.nlink() > 1
        {
            let temp = binary.with_extension("single-link.tmp");
            fs::copy(&binary, &temp).map_err(|_| "Failed to copy native binary")?;
            fs::rename(&temp, &binary).map_err(|_| "Failed to replace native binary")?;
        }
    }
    let mut task = match &stage {
        NativeStage::Release(_, command)
            if [
                "verify-build",
                "prepare-publication",
                "prepare-private-final-archive",
                "verify-private-final-archive",
                "sign-public-candidates",
            ]
            .contains(command) =>
        {
            crate::publication_candidates::verification_environment(env)
        }
        NativeStage::Release(_, _) => task_environment(env),
        NativeStage::Ci(request) => crate::ci_request::ci_child_environment(env, request)?,
        NativeStage::WindowsSdk(_, _) | NativeStage::RetainedArtifacts(_, _) => {
            crate::retained_artifacts::storage_environment(env, src, source_sha)?
        }
    };
    for key in [
        "HOME",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "RUSTUP_HOME",
        "CARGO_BUILD_JOBS",
    ] {
        task.insert(key.into(), build[key].clone());
    }
    let (arguments, timeout) = match &stage {
        NativeStage::Release(request, command) => {
            task.insert("RELEASE_REQUEST".into(), request.normalized()?);
            task.remove("WINDOWS_PREVIEW_OUTPUT_DIR");
            crate::private_final_archive::forward(
                env,
                request,
                required(env, "RELEASE_TARGET")?,
                command,
                &mut task,
            )?;
            if crate::private_final_archive::command(command) {
                task.remove("SIGNING_CONFIG");
                task.remove("APPLE_CONFIG");
            }
            if request.preview_windows_self_sign && required(env, "RELEASE_TARGET")? == "windows" {
                required(env, "DIAGNOSTICS_PUBLIC_KEY")?;
                task.insert(
                    "WINDOWS_PREVIEW_OUTPUT_DIR".into(),
                    crate::retained_artifacts::preview_directory(env)?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            task.insert(
                "RELEASE_INTEGRATION_SOURCE_REPOSITORY".into(),
                required(env, "SOURCE_REPOSITORY")?.into(),
            );
            task.insert(
                "RELEASE_INTEGRATION_SOURCE_REF".into(),
                format!("refs/heads/{}", required(env, "SOURCE_BRANCH")?),
            );
            let args = if crate::private_final_archive::command(command) {
                task.insert(
                    "LEAP_RELEASE_SOURCE_ROOT".into(),
                    src.to_string_lossy().into_owned(),
                );
                crate::private_final_archive::arguments(command, env, &work)?
            } else if *command == "sign-public-candidates" {
                crate::publication_candidates::request(env)?;
                task.insert(
                    "LEAP_RELEASE_SOURCE_ROOT".into(),
                    src.to_string_lossy().into_owned(),
                );
                vec![
                    "helper".into(),
                    "artifacts".into(),
                    "sign-public-candidates".into(),
                    "--input".into(),
                    required(env, "INPUT_PUBLIC_CANDIDATES_DIR")?.into(),
                    "--work".into(),
                    work.to_string_lossy().into_owned(),
                ]
            } else if *command == "prepare-publication" {
                crate::publication_candidates::request(env)?;
                task.remove("SIGNING_CONFIG");
                task.remove("APPLE_CONFIG");
                let publication = crate::publication_candidates::directory(env)?;
                if fs::symlink_metadata(&publication).is_ok() {
                    return Err("Public publication preparation must be fresh");
                }
                directory(&publication)?;
                task.insert(
                    "LEAP_RELEASE_SOURCE_ROOT".into(),
                    src.to_string_lossy().into_owned(),
                );
                vec![
                    "helper".into(),
                    "artifacts".into(),
                    "prepare-publication-candidates".into(),
                    "--input".into(),
                    required(env, "INPUT_PUBLIC_CANDIDATES_DIR")?.into(),
                    "--output".into(),
                    publication.join("files").to_string_lossy().into_owned(),
                    "--plan".into(),
                    publication.join("plan.json").to_string_lossy().into_owned(),
                    "--work".into(),
                    work.to_string_lossy().into_owned(),
                ]
            } else {
                vec![
                    if *command == "agent-run" {
                        "agent-run".into()
                    } else if *command == "verify-build" {
                        "verify-build".into()
                    } else {
                        "run".into()
                    },
                    "--root".into(),
                    src.to_string_lossy().into_owned(),
                    "--work-dir".into(),
                    work.to_string_lossy().into_owned(),
                ]
            };
            let timeout = match required(env, "RELEASE_TARGET")? {
                "integration" => 21600,
                "installation" => 10800,
                _ => 10000,
            };
            (args, timeout)
        }
        NativeStage::Ci(request) => {
            let request_path = work.join("ci-request.json");
            let raw = serde_json::to_vec(request).map_err(|_| "Invalid CI request encoding")?;
            private_file(&request_path, &raw)?;
            task.insert("CARGO_BUILD_JOBS".into(), "2".into());
            (
                vec![
                    "ci".into(),
                    "--root".into(),
                    src.to_string_lossy().into_owned(),
                    "--work-dir".into(),
                    work.to_string_lossy().into_owned(),
                    "--request".into(),
                    request_path.to_string_lossy().into_owned(),
                ],
                10000,
            )
        }
        NativeStage::WindowsSdk(_, operation) => {
            let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
                .canonicalize()
                .map_err(|_| "SDK runner directory invalid")?;
            let prefix = runner.join("windows-native-sdk");
            task.insert(
                "LEAP_RELEASE_SOURCE_ROOT".into(),
                src.to_string_lossy().into_owned(),
            );
            (
                vec![
                    "helper".into(),
                    "artifacts".into(),
                    format!("windows-sdk-{operation}"),
                    "--prefix".into(),
                    prefix.to_string_lossy().into_owned(),
                    "--manifest-sha256".into(),
                    required(env, "LEAPTERM_WINDOWS_SDK_MANIFEST_SHA256")?.into(),
                ],
                10000,
            )
        }
        NativeStage::RetainedArtifacts(request, artifact) => {
            task.insert("RELEASE_ARTIFACT_KIND".into(), artifact.kind.clone());
            task.insert("RELEASE_ARTIFACT_SCOPE".into(), artifact.scope.clone());
            if artifact.kind == "agent-packages" {
                (
                    vec![
                        "helper".into(),
                        "artifacts".into(),
                        "retain-agent-packages".into(),
                        "--directory".into(),
                        artifact.path.to_string_lossy().into_owned(),
                        "--platform".into(),
                        required(env, "LEAP_AGENT_PLATFORM")?.into(),
                        "--version".into(),
                        request.version.clone(),
                        "--scope".into(),
                        artifact.scope.clone(),
                    ],
                    900,
                )
            } else {
                (
                    vec![
                        "helper".into(),
                        "artifacts".into(),
                        "retain-build-artifacts".into(),
                        "--input".into(),
                        artifact.path.to_string_lossy().into_owned(),
                        "--kind".into(),
                        artifact.kind.clone(),
                        "--scope".into(),
                        artifact.scope.clone(),
                    ],
                    600,
                )
            }
        }
    };
    task.insert("SOURCE".into(), src.to_string_lossy().into_owned());
    task.insert(
        "PUBLIC_BUILDER_SHA".into(),
        required(env, "GITHUB_SHA")?.into(),
    );

    for (key, name) in [
        ("PRIVATE_BOOTSTRAP_LOG", "bootstrap.log"),
        ("PRIVATE_DIAGNOSTIC_LOG", "task.log"),
        ("RELEASE_STATUS_FILE", "status.json"),
    ] {
        task.insert(key.into(), root.join(name).to_string_lossy().into_owned());
    }
    println!("Native release phase: private-task");
    if matches!(&stage, NativeStage::Release(_, _))
        && cfg!(windows)
        && (required(env, "RELEASE_TARGET")? == "windows"
            || (required(env, "RELEASE_TARGET")? == "integration"
                && env.get("LEAP_INTEGRATION_PLATFORM").map(String::as_str) == Some("windows")))
    {
        let runner = PathBuf::from(required(env, "RUNNER_TEMP")?)
            .canonicalize()
            .map_err(|_| "SDK runner directory invalid")?;
        let prefix = runner.join("windows-native-sdk");
        let sdk_task = crate::retained_artifacts::storage_environment(env, src, source_sha)?;
        process::run(
            &binary,
            &[
                "helper".into(),
                "artifacts".into(),
                "windows-sdk-get".into(),
                "--prefix".into(),
                prefix.to_string_lossy().into_owned(),
                "--manifest-sha256".into(),
                required(env, "LEAPTERM_WINDOWS_SDK_MANIFEST_SHA256")?.into(),
            ],
            root,
            &sdk_task,
            Duration::from_secs(1000),
            Some(bootstrap),
        )?;
        task.insert(
            "LEAPTERM_FREERDP_PREFIX".into(),
            crate::retained_artifacts::ordinary(&prefix)?
                .to_string_lossy()
                .into_owned(),
        );
    }
    let outcome = process::run(
        &binary,
        &arguments,
        root,
        &task,
        Duration::from_secs(timeout),
        Some(bootstrap),
    );
    let task_log = root.join("task.log");
    let task_empty = fs::symlink_metadata(&task_log)
        .map(|meta| meta.len() == 0)
        .unwrap_or(true);
    if task_empty {
        for fallback in ["native-ios.log", "build.log"] {
            let log_path = work.join(fallback);
            if let Ok(meta) = fs::symlink_metadata(&log_path)
                && meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.len() <= 8 * 1024 * 1024
            {
                let _ = fs::copy(&log_path, &task_log);
                break;
            }
        }
    }
    outcome.map_err(|error| match error {
        "Build command failed; inspect private diagnostics" => {
            "Private release task failed; native CLI compilation and tests passed; inspect private diagnostics"
        }
        _ => error,
    })?;
    frozen.verify()?;
    source::verify_tools(src, &checkout)?;
    source::verify(src, source_sha, &checkout, false, 0)?;
    if matches!(&stage, NativeStage::Ci(_)) {
        // The authenticated source-CI parent owns its exact receipt handoff.
        // This compiler boundary has no release output mirror or upload role.
        return Ok(());
    }
    if let NativeStage::Release(_, operation) = &stage
        && crate::private_final_archive::command(operation)
    {
        let proof = crate::private_final_archive::capture(env, &work, operation)?;
        write_outputs(env, &[("private_archive_proof_sha256", &proof)])?;
    }
    if let NativeStage::Release(_, "prepare-publication") = &stage {
        let (verifier, plan) = crate::publication_candidates::retain_verifier(env, &binary)?;
        write_outputs(
            env,
            &[
                ("native_verifier_sha256", &verifier),
                ("publication_plan_sha256", &plan),
            ],
        )?;
    }
    if let NativeStage::Release(request, _) = &stage
        && request.preview_windows_self_sign
        && required(env, "RELEASE_TARGET")? == "windows"
    {
        crate::retained_artifacts::seal_evaluation(env, request, root, bootstrap)?;
    }
    let workspace =
        std::env::current_dir().map_err(|_| "Workspace output directory unavailable")?;
    export_workspace_outputs(&work, &workspace)
}

fn export_workspace_outputs(work: &Path, workspace: &Path) -> Result<()> {
    let outputs_dir = work.join("outputs");
    match fs::symlink_metadata(&outputs_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Native workspace outputs unavailable"),
        Ok(_) => crate::guards::directory(&outputs_dir)?,
    }
    let dest = workspace.join("release-work/outputs");
    fs::create_dir_all(&dest).map_err(|_| "Native workspace output directory unavailable")?;
    crate::guards::directory(&dest)?;
    // Public candidate custody belongs to the native catalog exporter. This
    // workspace mirror includes private updater handoffs and is never its input.
    for entry in fs::read_dir(&outputs_dir).map_err(|_| "Native workspace outputs unreadable")? {
        let entry = entry.map_err(|_| "Native workspace output entry unreadable")?;
        if entry
            .file_type()
            .map_err(|_| "Native workspace output entry unavailable")?
            .is_file()
        {
            fs::copy(entry.path(), dest.join(entry.file_name()))
                .map_err(|_| "Native workspace output copy failed")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod workspace_output_tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fixture {
        _temporary: tempfile::TempDir,
        work: PathBuf,
        workspace: PathBuf,
        runner: PathBuf,
        target: String,
    }
    impl Fixture {
        fn new(target: &str, mode: &str) -> Self {
            let temporary =
                tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
            let work = temporary.path().join("private-task");
            let workspace = temporary.path().join("workspace");
            let runner = temporary.path().join("runner");
            for path in [work.join("outputs"), workspace.clone(), runner.clone()] {
                fs::create_dir_all(path).unwrap();
            }
            let suffixes: &[&str] = match target {
                "linux" => &[
                    "linux-x64.tar.gz",
                    "services-linux-x64.tar.gz",
                    "agent-linux-amd64.deb",
                    "agent-linux-x86_64.rpm",
                ],
                "windows" => &["windows-x64.zip", "services-windows-x64.zip"],
                "macos" => &["macos-arm64.zip", "services-macos-arm64.tar.gz"],
                _ => panic!("unknown fixture target"),
            };
            let handoff = runner.join("reviewed-public-candidates").join(target);
            if mode == "option1" {
                fs::create_dir_all(&handoff).unwrap();
            }
            for suffix in suffixes {
                let name = format!("leapterm-1.2.3-{suffix}");
                let bytes = format!("public package fixture {name}").into_bytes();
                fs::write(work.join("outputs").join(&name), &bytes).unwrap();
                if mode == "option1" {
                    fs::write(handoff.join(&name), &bytes).unwrap();
                    fs::write(
                        handoff.join(format!("{name}.sha256")),
                        b"native sidecar fixture",
                    )
                    .unwrap();
                }
            }
            if mode != "build-only" {
                let architecture = if target == "macos" { "arm64" } else { "x64" };
                fs::write(
                    work.join("outputs").join(format!(
                        "leapterm-1.2.3-updates-{target}-{architecture}.zip"
                    )),
                    b"private updater fixture",
                )
                .unwrap();
            }
            if mode == "option1" {
                // Opaque native handoff bytes: these file-boundary fixtures do
                // not establish producer or package-signing authority.
                fs::write(
                    handoff.join("candidate-manifest.json"),
                    b"native manifest fixture",
                )
                .unwrap();
            }
            Self {
                _temporary: temporary,
                work,
                workspace,
                runner,
                target: target.into(),
            }
        }
        fn handoff(&self) -> PathBuf {
            self.runner
                .join("reviewed-public-candidates")
                .join(&self.target)
        }
        fn export(&self) -> Result<()> {
            export_workspace_outputs(&self.work, &self.workspace)
        }
        fn assert_workspace_mirror(&self) {
            assert_eq!(
                inventory(&self.workspace.join("release-work/outputs")),
                inventory(&self.work.join("outputs"))
            );
            assert!(!self.work.join("release-work/outputs").exists());
        }
    }
    fn inventory(path: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    fn desktop_handoff(target: &str) {
        let fixture = Fixture::new(target, "option1");
        let before = inventory(&fixture.handoff());
        assert!(before.contains_key("candidate-manifest.json"));
        assert!(before.keys().any(|name| name.ends_with(".sha256")));
        assert!(!before.keys().any(|name| name.contains("-updates-")));
        fixture.export().unwrap();
        fixture.assert_workspace_mirror();
        assert_eq!(inventory(&fixture.handoff()), before);
    }
    #[test]
    fn full_option1_linux_workspace_export_keeps_exact_public_handoff() {
        desktop_handoff("linux");
    }
    #[test]
    fn full_option1_windows_workspace_export_keeps_exact_public_handoff() {
        desktop_handoff("windows");
    }
    #[test]
    fn full_option1_macos_workspace_export_keeps_exact_public_handoff() {
        desktop_handoff("macos");
    }
    #[test]
    fn build_only_and_legacy_workspace_exports_do_not_create_public_handoffs() {
        for mode in ["build-only", "legacy-acceptance"] {
            for target in ["linux", "windows", "macos"] {
                let fixture = Fixture::new(target, mode);
                assert!(!fixture.handoff().exists());
                fixture.export().unwrap();
                fixture.assert_workspace_mirror();
                assert!(!fixture.handoff().exists());
            }
        }
    }
    #[test]
    fn workspace_export_reports_a_blocked_destination() {
        let fixture = Fixture::new("linux", "build-only");
        fs::create_dir(fixture.workspace.join("release-work")).unwrap();
        fs::write(
            fixture.workspace.join("release-work/outputs"),
            b"occupied destination",
        )
        .unwrap();
        assert!(fixture.export().is_err());
    }
    #[test]
    fn stages_without_native_outputs_do_not_create_a_workspace_mirror() {
        let fixture = Fixture::new("linux", "build-only");
        fs::remove_dir_all(fixture.work.join("outputs")).unwrap();
        fixture.export().unwrap();
        assert!(!fixture.workspace.join("release-work").exists());
        assert!(!fixture.handoff().exists());
    }
}
