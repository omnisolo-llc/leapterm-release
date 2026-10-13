use omni_release_launcher::{Environment, hosted_inputs};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn workflow(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    let raw = fs::read_to_string(path).unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    serde_json::to_value(yaml).unwrap()
}

#[test]
fn source_ci_runs_every_canonical_cell_under_protected_authority() {
    let workflow = workflow("source-ci.yml");
    let job = &workflow["jobs"]["source_ci"];
    assert_eq!(job["environment"], "source-ci-authority");
    let cells = job["strategy"]["matrix"]["stage"].as_array().unwrap();
    let actual: Vec<_> = cells.iter().map(|value| value.as_str().unwrap()).collect();
    assert_eq!(actual, omni_release_launcher::ci_request::CI_STAGES);
    assert_eq!(job["runs-on"], "ubuntu-24.04");
    let execute = job["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "execute_source_ci")
        .unwrap();
    assert_eq!(execute["run"], "bash ci/native-release/run.sh source-ci");
    for name in [
        "SOURCE_CI_APPROVAL_READ_TOKEN",
        "SOURCE_METADATA_READ_TOKEN",
        "SOURCE_CI_HANDOFF_WRITE_TOKEN",
    ] {
        assert!(execute["env"].get(name).is_some(), "{name}");
    }
    for step in job["steps"].as_array().unwrap() {
        assert!(
            !step
                .get("uses")
                .and_then(Value::as_str)
                .is_some_and(|name| name.contains("upload-artifact")
                    || name.contains("download-artifact")
                    || name.contains("rust-cache"))
        );
    }
}

#[test]
fn legacy_release_policy_debt_does_not_replace_source_ci_authority_checks() {
    let request = serde_json::json!({"identity":{"source_repository":"omnisolo-llc/omniterm","source_sha":"a".repeat(40),
        "builder_repository":"omnisolo-llc/omniterm-release","builder_sha":"b".repeat(40),"run_id":"123","attempt":"1"},
        "source_ref":"refs/heads/main","stage":"source","shard_index":0,"shard_count":1});
    let env = Environment::from([
        ("SOURCE_CI_REQUEST".into(), request.to_string()),
        ("INPUT_CATALOG_SHA256".into(), "c".repeat(64)),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("GITHUB_RUN_ID".into(), "123".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
    ]);
    let result = omni_release_launcher::source_ci::run(&env);
    assert!(
        result.is_err(),
        "Missing current approval must still refuse acquisition"
    );
    assert_ne!(
        result,
        Err("Public source-CI workflow policy refused"),
        "Only the new source graph is enforced before legacy cutover"
    );
}

#[test]
fn all_native_installation_cells_forward_the_materialized_control_path() {
    let workflow = workflow("release.yml");
    let job = &workflow["jobs"]["installation"];
    let steps = job["steps"].as_array().unwrap();
    let prepare = steps
        .iter()
        .find(|step| step["id"] == "installed_vpn_control")
        .unwrap();
    assert_eq!(
        prepare["run"],
        "bash ci/native-release/run.sh prepare-installed-control"
    );
    assert!(
        prepare["env"]
            .get("OMNI_VPN_INSTALLED_CONTROL_JSON")
            .is_some()
    );
    let execute = steps
        .iter()
        .find(|step| step["env"]["RELEASE_TARGET"] == "installation")
        .unwrap();
    assert_eq!(
        execute["env"]["OMNI_VPN_INSTALLED_CONTROL_FILE"],
        "${{ steps.installed_vpn_control.outputs.control_file }}"
    );
    let cells = job["strategy"]["matrix"]["include"].as_array().unwrap();
    for platform in ["linux", "macos", "windows", "android", "ios"] {
        assert!(cells.iter().any(|cell| cell["platform"] == platform));
    }
}

#[test]
fn hosted_integration_provides_original_source_pair_profile() {
    let workflow = workflow("release.yml");
    let steps = workflow["jobs"]["integration"]["steps"].as_array().unwrap();
    let prepare = steps
        .iter()
        .find(|step| step["id"] == "protected_source_pair")
        .unwrap();
    assert_eq!(
        prepare["run"],
        "bash ci/native-release/run.sh prepare-protected-source-pair"
    );
    let execute = steps
        .iter()
        .find(|step| step["env"]["RELEASE_TARGET"] == "integration")
        .unwrap();
    assert_eq!(
        execute["env"]["OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_FILE"],
        "${{ steps.protected_source_pair.outputs.profile_file }}"
    );
}

fn hosted_environment(runner: &Path, output: &Path) -> Environment {
    Environment::from([
        ("GITHUB_ACTIONS".into(), "true".into()),
        ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
        (
            "GITHUB_REPOSITORY".into(),
            "omnisolo-llc/omniterm-release".into(),
        ),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        (
            "GITHUB_WORKFLOW_REF".into(),
            "omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main".into(),
        ),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("RUNNER_TEMP".into(), runner.to_string_lossy().into_owned()),
        (
            "GITHUB_OUTPUT".into(),
            output.to_string_lossy().into_owned(),
        ),
        ("OMNI_INTEGRATION_PLATFORM".into(), "android".into()),
    ])
}

fn input_boundary<T>(
    stage: &str,
    result: omni_release_launcher::Result<T>,
) -> omni_release_launcher::Result<T> {
    if let Err(error) = &result {
        let category = match *error {
            "Windows hosted input owner command failed" => "windows-owner-command",
            "Windows hosted input ACL command failed" => "windows-acl-command",
            "Hosted input owner unavailable" | "Hosted input owner invalid" => "owner-output",
            "Hosted input directory unavailable" | "Directory unavailable" | "Unsafe directory" => {
                "directory"
            }
            "Cannot create private release file"
            | "Cannot write private release file"
            | "Hosted input unavailable" => "file",
            "No-follow file handle unavailable"
            | "Regular file unavailable"
            | "Unsafe Windows file handle" => "handle",
            "Expected bounded regular file"
            | "File replaced or hardlinked"
            | "File replaced during open"
            | "File identity unavailable"
            | "File identity changed"
            | "Hardlinked workflow output" => "identity",
            "Hosted input cleanup boundary" | "Hosted input cleanup file unavailable" => "cleanup",
            _ => "other",
        };
        eprintln!("Native hosted input boundary: {stage} {category}");
    }
    result
}

#[test]
fn hosted_input_custody_preserves_original_bytes_and_removes_its_exact_file() {
    let runner = tempfile::tempdir().unwrap();
    let output = runner.path().join("output");
    fs::write(&output, "").unwrap();
    let raw = "{\n  \"schema\":1, \"campaigns\":[{},{},{},{}]\n}\n";
    let mut env = hosted_environment(runner.path(), &output);
    env.insert("OMNI_VPN_INSTALLED_CONTROL_JSON".into(), raw.into());
    input_boundary(
        "prepare-control",
        hosted_inputs::run("prepare-installed-control", &env),
    )
    .unwrap();
    let record = fs::read_to_string(&output).unwrap();
    let path = std::path::PathBuf::from(record.trim().strip_prefix("control_file=").unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), raw);
    let canonical_runner = runner.path().canonicalize().unwrap();
    assert_eq!(
        path.parent().unwrap().parent(),
        Some(canonical_runner.as_path())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    env.insert(
        "OMNI_VPN_INSTALLED_CONTROL_FILE".into(),
        path.to_string_lossy().into_owned(),
    );
    input_boundary("cleanup-control", hosted_inputs::cleanup(&env)).unwrap();
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn hosted_input_materialization_rejects_changed_pin_duplicate_fields_and_missing_native_input() {
    let runner = tempfile::tempdir().unwrap();
    let output = runner.path().join("output");
    fs::write(&output, "").unwrap();
    let raw =
        "{\"schema\":\"omniterm.protected-desktop.source-profile.v1\",\"platform\":\"android\"}";
    let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(
        input_boundary(
            "materialize-profile",
            hosted_inputs::materialize(
                runner.path(),
                "omni-protected-source-pair-",
                "profile.json",
                raw,
                Some(&digest)
            ),
        )
        .is_ok()
    );
    assert!(
        hosted_inputs::materialize(
            runner.path(),
            "omni-protected-source-pair-",
            "profile.json",
            raw,
            Some(&"0".repeat(64))
        )
        .is_err()
    );
    assert!(
        hosted_inputs::materialize(
            runner.path(),
            "omni-protected-source-pair-",
            "profile.json",
            "{\"platform\":\"ios\",\"platform\":\"android\"}",
            None
        )
        .is_err()
    );
    let env = hosted_environment(runner.path(), &output);
    assert!(hosted_inputs::run("prepare-installed-control", &env).is_err());
    assert!(hosted_inputs::run("prepare-protected-source-pair", &env).is_err());
    assert!(fs::read_to_string(&output).unwrap().is_empty());
}

#[test]
fn hosted_cleanup_cannot_delete_an_unrecognized_file_inside_a_matching_prefix() {
    let runner = tempfile::tempdir().unwrap();
    let output = runner.path().join("output");
    fs::write(&output, "").unwrap();
    let input = input_boundary(
        "materialize-control",
        hosted_inputs::materialize(
            runner.path(),
            "omni-installed-control-",
            "control.json",
            "{}",
            None,
        ),
    )
    .unwrap();
    let foreign = input.parent().unwrap().join("foreign-private-input.json");
    fs::rename(&input, &foreign).unwrap();
    let mut env = hosted_environment(runner.path(), &output);
    env.insert(
        "OMNI_VPN_INSTALLED_CONTROL_FILE".into(),
        foreign.to_string_lossy().into_owned(),
    );
    assert!(hosted_inputs::cleanup(&env).is_err());
    assert!(foreign.exists());
}

#[test]
fn failed_workflow_output_publication_removes_the_protected_input() {
    for (command, input, raw) in [
        (
            "prepare-installed-control",
            "OMNI_VPN_INSTALLED_CONTROL_JSON",
            "{\"schema\":1,\"campaigns\":[{},{},{},{}]}",
        ),
        (
            "prepare-protected-source-pair",
            "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_JSON",
            "{\"schema\":\"omniterm.protected-desktop.source-profile.v1\",\"platform\":\"android\"}",
        ),
    ] {
        for failure in [
            "missing-output-variable",
            "missing-output-file",
            "output-is-directory",
        ] {
            let runner = tempfile::tempdir().unwrap();
            let output = runner.path().join("output");
            let mut env = hosted_environment(runner.path(), &output);
            env.insert(input.into(), raw.into());
            env.insert(
                "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_SHA256".into(),
                format!("{:x}", Sha256::digest(raw.as_bytes())),
            );
            if failure == "missing-output-variable" {
                env.remove("GITHUB_OUTPUT");
            } else if failure == "output-is-directory" {
                fs::create_dir(&output).unwrap();
            }
            assert!(hosted_inputs::run(command, &env).is_err());
            let retained = fs::read_dir(runner.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.is_dir() && path != &output)
                .collect::<Vec<_>>();
            assert!(
                retained.is_empty(),
                "{command}/{failure} left protected input directories: {retained:?}"
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn hosted_input_identity_and_acl_tools_ignore_inert_path_shadows() {
    use std::process::Command;
    let runner = tempfile::tempdir().unwrap();
    let shadow = runner.path().join("shadow");
    fs::create_dir(&shadow).unwrap();
    for name in ["whoami.exe", "icacls.exe"] {
        // This owned stand-in rejects native identity/ACL arguments before
        // attempting any network request. Relative tool lookup must fail.
        fs::copy(env!("CARGO_BIN_EXE_source-api-fixture"), shadow.join(name)).unwrap();
    }
    let output_file = runner.path().join("output");
    fs::write(&output_file, "").unwrap();
    let raw = "{\n  \"schema\":1, \"campaigns\":[{},{},{},{}]\n}\n";
    let mut env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    env.extend(hosted_environment(runner.path(), &output_file));
    env.insert("PATH".into(), shadow.to_string_lossy().into_owned());
    env.insert("OMNI_VPN_INSTALLED_CONTROL_JSON".into(), raw.into());
    let prepared = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("prepare-installed-control")
        .current_dir(runner.path())
        .env_clear()
        .envs(&env)
        .output()
        .unwrap();
    assert!(
        prepared.status.success(),
        "Native Windows identity and ACL tools must ignore PATH shadows"
    );
    let record = fs::read_to_string(&output_file).unwrap();
    let path = std::path::PathBuf::from(record.trim().strip_prefix("control_file=").unwrap());
    assert_eq!(fs::read(&path).unwrap(), raw.as_bytes());
    let canonical_runner = runner.path().canonicalize().unwrap();
    assert_eq!(
        path.parent().unwrap().parent(),
        Some(canonical_runner.as_path())
    );
    env.insert(
        "OMNI_VPN_INSTALLED_CONTROL_FILE".into(),
        path.to_string_lossy().into_owned(),
    );
    let cleanup = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("cleanup-hosted-inputs")
        .current_dir(runner.path())
        .env_clear()
        .envs(&env)
        .output()
        .unwrap();
    assert!(cleanup.status.success());
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn hosted_profile_admission_preserves_original_bytes_for_each_supported_version() {
    for version in ["v1", "v2"] {
        let runner = tempfile::tempdir().unwrap();
        let output = runner.path().join("output");
        fs::write(&output, "").unwrap();
        let raw = format!(
            "{{\n  \"schema\": \"omniterm.protected-desktop.source-profile.{version}\",\n  \"platform\": \"android\"\n}}\n"
        );
        let held_pin = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let mut env = hosted_environment(runner.path(), &output);
        env.insert(
            "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_JSON".into(),
            raw.clone(),
        );
        env.insert(
            "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_SHA256".into(),
            held_pin,
        );
        input_boundary(
            "materialize-profile",
            hosted_inputs::run("prepare-protected-source-pair", &env),
        )
        .unwrap();
        let record = fs::read_to_string(&output).unwrap();
        let path = std::path::PathBuf::from(record.trim().strip_prefix("profile_file=").unwrap());
        assert_eq!(fs::read(&path).unwrap(), raw.as_bytes(), "{version}");
        let canonical_runner = runner.path().canonicalize().unwrap();
        assert_eq!(
            path.parent().unwrap().parent(),
            Some(canonical_runner.as_path()),
            "{version}"
        );
        env.insert(
            "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_FILE".into(),
            path.to_string_lossy().into_owned(),
        );
        hosted_inputs::cleanup(&env).unwrap();
        assert!(!path.exists(), "{version}");
        assert!(!path.parent().unwrap().exists(), "{version}");
    }
}

#[test]
fn hosted_profile_admission_refuses_wrong_platform_unknown_version_and_changed_original_pin() {
    for change in ["platform", "version", "pin", "original-bytes"] {
        let runner = tempfile::tempdir().unwrap();
        let output = runner.path().join("output");
        fs::write(&output, "").unwrap();
        let version = if change == "version" { "v3" } else { "v2" };
        let platform = if change == "platform" {
            "ios"
        } else {
            "android"
        };
        let original = format!(
            "{{\n  \"schema\": \"omniterm.protected-desktop.source-profile.{version}\",\n  \"platform\": \"{platform}\"\n}}\n"
        );
        let held_pin = if change == "pin" {
            "0".repeat(64)
        } else {
            format!("{:x}", Sha256::digest(original.as_bytes()))
        };
        let raw = if change == "original-bytes" {
            format!(" {original}")
        } else {
            original
        };
        let mut env = hosted_environment(runner.path(), &output);
        env.insert("OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_JSON".into(), raw);
        env.insert(
            "OMNI_PROTECTED_DESKTOP_SOURCE_PROFILE_SHA256".into(),
            held_pin,
        );
        let expected = if ["pin", "original-bytes"].contains(&change) {
            "Protected hosted input digest changed"
        } else {
            "Protected source pair original profile missing"
        };
        assert_eq!(
            hosted_inputs::run("prepare-protected-source-pair", &env),
            Err(expected),
            "{change}"
        );
        assert!(fs::read_to_string(&output).unwrap().is_empty(), "{change}");
        assert!(
            fs::read_dir(runner.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_type()
                .unwrap()
                .is_dir()),
            "{change}"
        );
    }
}
