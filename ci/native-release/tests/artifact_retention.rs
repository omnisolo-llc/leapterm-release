use omni_release_launcher::{Environment, input::Request, retained_artifacts};
use serde_json::json;
use std::{fs, path::Path};

fn environment(runner: &Path) -> Environment {
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
        ("GITHUB_RUN_ID".into(), "42".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "2".into()),
        ("SOURCE_REPOSITORY".into(), "omnisolo-llc/omniterm".into()),
        ("SOURCE_BRANCH".into(), "main".into()),
        ("RESOLVED_SOURCE_SHA".into(), "a".repeat(40)),
        ("RUNNER_TEMP".into(), runner.to_string_lossy().into_owned()),
        ("STORAGE_CONFIG".into(), "fixture-selected-storage".into()),
        ("RELEASE_ARTIFACT_KIND".into(), "diagnostics".into()),
        ("RELEASE_ARTIFACT_SCOPE".into(), "verify-windows".into()),
        ("RELEASE_TARGET".into(), "windows".into()),
    ])
}
fn request(preview: bool) -> Request {
    Request::parse(&json!({"build_only":true,"verify_target":"windows","preview_windows_self_sign":preview,"source_sha":"a".repeat(40),"build_number":"42"}).to_string()).unwrap()
}
#[test]
fn agent_retention_binds_the_approved_source_version_platform_and_separate_storage_kind() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = environment(temp.path());
    let pin = omni_release_launcher::agent::approved_source().unwrap();
    let raw = json!({"build_only":true,"source_sha":pin.source_sha,"version":pin.version,
        "build_number":"1","ios_action":"skip","automatic_release":false,"include_selfhost":true})
    .to_string();
    env.insert(
        "GITHUB_WORKFLOW_REF".into(),
        omni_release_launcher::agent::WORKFLOW_REF.into(),
    );
    env.insert("RELEASE_REQUEST".into(), raw.clone());
    env.insert("SOURCE_BRANCH".into(), pin.source_branch);
    env.insert("RESOLVED_SOURCE_SHA".into(), pin.source_sha.clone());
    env.insert("RELEASE_TARGET".into(), "linux".into());
    env.insert("OMNI_AGENT_PLATFORM".into(), "linux-x86_64".into());
    env.insert("RELEASE_ARTIFACT_SCOPE".into(), "agent-linux-x86-64".into());
    let child =
        retained_artifacts::storage_environment(&env, temp.path(), &pin.source_sha).unwrap();
    assert_eq!(child["RELEASE_STORAGE_KIND"], "agent");
    assert_eq!(child["OMNI_AGENT_VERSION"], pin.version);
    assert_eq!(child["OMNI_AGENT_PLATFORM"], "linux-x86_64");
    assert!(
        retained_artifacts::artifact(&env, &Request::parse(&raw).unwrap())
            .unwrap()
            .is_none()
    );
    env.insert(
        "RELEASE_ARTIFACT_SCOPE".into(),
        "agent-linux-aarch64".into(),
    );
    assert!(retained_artifacts::artifact(&env, &Request::parse(&raw).unwrap()).is_err());
    env.insert("OMNI_AGENT_PLATFORM".into(), "windows-x86_64".into());
    assert!(retained_artifacts::storage_environment(&env, temp.path(), &pin.source_sha).is_err());
}

#[test]
fn retention_child_gets_only_storage_authority_and_captured_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = environment(temp.path());
    for key in [
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "SIGNING_CONFIG",
        "DIAGNOSTICS_PUBLIC_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "BUILD_CONFIG",
        "RELEASE_REQUEST",
        "WINDOWS_PREVIEW_OUTPUT_DIR",
        "OMNI_PROVIDER_TOKEN",
        "GITHUB_OUTPUT",
    ] {
        env.insert(key.into(), "fixture-secret-not-to-inherit".into());
    }
    let child =
        retained_artifacts::storage_environment(&env, temp.path(), &"a".repeat(40)).unwrap();
    assert_eq!(child["STORAGE_CONFIG"], "fixture-selected-storage");
    assert_eq!(child["PUBLIC_BUILDER_SHA"], "b".repeat(40));
    assert_eq!(child["RESOLVED_SOURCE_SHA"], "a".repeat(40));
    assert_eq!(child["GITHUB_RUN_ATTEMPT"], "2");
    for key in [
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "SIGNING_CONFIG",
        "DIAGNOSTICS_PUBLIC_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "BUILD_CONFIG",
        "RELEASE_REQUEST",
        "WINDOWS_PREVIEW_OUTPUT_DIR",
        "OMNI_PROVIDER_TOKEN",
        "GITHUB_OUTPUT",
    ] {
        assert!(!child.contains_key(key), "{key}");
    }
    assert!(retained_artifacts::storage_environment(&env, temp.path(), &"c".repeat(40)).is_err());
    env.insert("PUBLIC_BUILDER_SHA".into(), "d".repeat(40));
    assert!(retained_artifacts::storage_environment(&env, temp.path(), &"a".repeat(40)).is_err());
}

#[test]
fn retention_cannot_select_files_or_turn_missing_evaluation_into_success() {
    let temp = tempfile::tempdir().unwrap();
    let physical_parent = temp.path().join("physical");
    fs::create_dir(&physical_parent).unwrap();
    fs::create_dir(physical_parent.join("runner")).unwrap();
    // An ancestor alias reproduces native temporary-directory spelling while
    // the runner leaf stays an ordinary directory on every platform.
    #[cfg(unix)]
    let runner_parent = {
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&physical_parent, &alias).unwrap();
        alias
    };
    #[cfg(not(unix))]
    let runner_parent = physical_parent;
    let runner = runner_parent.join("runner");
    let metadata = fs::symlink_metadata(&runner).unwrap();
    assert!(metadata.is_dir() && !metadata.is_symlink());
    let canonical_runner = runner.canonicalize().unwrap();
    #[cfg(unix)]
    assert_ne!(runner, canonical_runner);
    let mut env = environment(&runner);
    assert!(
        retained_artifacts::artifact(&env, &request(false))
            .unwrap()
            .is_none()
    );
    fs::create_dir(runner.join("encrypted-diagnostics")).unwrap();
    fs::write(
        runner.join("encrypted-diagnostics/diagnostics.sealed"),
        b"fixture-cipher",
    )
    .unwrap();
    let input = retained_artifacts::artifact(&env, &request(false))
        .unwrap()
        .unwrap();
    assert_eq!(
        input.path,
        canonical_runner.join("encrypted-diagnostics/diagnostics.sealed")
    );
    for value in [
        "../private",
        "verify/windows",
        "verify%2fwindows",
        "Verify",
        "",
    ] {
        env.insert("RELEASE_ARTIFACT_SCOPE".into(), value.into());
        assert!(retained_artifacts::artifact(&env, &request(false)).is_err());
    }
    env.insert("RELEASE_ARTIFACT_SCOPE".into(), "verify-windows".into());
    env.insert("RELEASE_ARTIFACT_KIND".into(), "evaluation".into());
    assert!(retained_artifacts::artifact(&env, &request(false)).is_err());
    assert!(retained_artifacts::artifact(&env, &request(true)).is_err());
    fs::create_dir(runner.join("encrypted-evaluation")).unwrap();
    fs::write(
        runner.join("encrypted-evaluation/evaluation.sealed"),
        b"fixture-cipher",
    )
    .unwrap();
    assert!(
        retained_artifacts::artifact(&env, &request(true))
            .unwrap()
            .is_some()
    );
    env.insert("RELEASE_ARTIFACT_SCOPE".into(), "downloads-windows".into());
    assert!(retained_artifacts::artifact(&env, &request(true)).is_err());
}
