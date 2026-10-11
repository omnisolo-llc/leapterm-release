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
    let request=serde_json::json!({"identity":{"source_repository":"omnisolo-llc/omniterm","source_sha":"a".repeat(40),
        "builder_repository":"omnisolo-llc/omniterm-release","builder_sha":"b".repeat(40),"run_id":"123","attempt":"1"},
        "source_ref":"refs/heads/main","stage":"source","shard_index":0,"shard_count":1});
    let env=Environment::from([
        ("SOURCE_CI_REQUEST".into(),request.to_string()),("INPUT_CATALOG_SHA256".into(),"c".repeat(64)),
        ("GITHUB_SHA".into(),"b".repeat(40)),("GITHUB_RUN_ID".into(),"123".into()),("GITHUB_RUN_ATTEMPT".into(),"1".into()),
    ]);
    let result=omni_release_launcher::source_ci::run(&env);
    assert!(result.is_err(),"Missing current approval must still refuse acquisition");
    assert_ne!(result,Err("Public source-CI workflow policy refused"),"Only the new source graph is enforced before legacy cutover");
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

#[test]
fn hosted_input_custody_preserves_original_bytes_and_removes_its_exact_file() {
    let runner = tempfile::tempdir().unwrap();
    let output = runner.path().join("output");
    fs::write(&output, "").unwrap();
    let raw = "{\n  \"schema\":1, \"campaigns\":[{},{},{},{}]\n}\n";
    let mut env = hosted_environment(runner.path(), &output);
    env.insert("OMNI_VPN_INSTALLED_CONTROL_JSON".into(), raw.into());
    hosted_inputs::run("prepare-installed-control", &env).unwrap();
    let record = fs::read_to_string(&output).unwrap();
    let path = std::path::PathBuf::from(record.trim().strip_prefix("control_file=").unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), raw);
    assert_eq!(path.parent().unwrap().parent(), Some(runner.path()));
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
    hosted_inputs::cleanup(&env).unwrap();
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
        hosted_inputs::materialize(
            runner.path(),
            "omni-protected-source-pair-",
            "profile.json",
            raw,
            Some(&digest)
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
    let input = hosted_inputs::materialize(
        runner.path(),
        "omni-installed-control-",
        "control.json",
        "{}",
        None,
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
