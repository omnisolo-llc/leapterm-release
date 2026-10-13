use omni_release_launcher::{
    Environment,
    input::{RELEASE_TARGETS, Request, validate_approval},
    launch::task_environment,
};
use std::{fs, process::Command};

#[test]
fn generic_commands_reach_authority_gate_without_a_legacy_branch() {
    for command in ["run", "agent-run"] {
        let result = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .arg(command)
            .env_clear()
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("authority"),
            "{command}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
#[test]
fn protected_approval_command_exports_only_matching_pins() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    for requested in [
        "a".repeat(40),
        "c".repeat(40),
        "bad\nsource_sha=evil".into(),
    ] {
        fs::write(&output, "").unwrap();
        let status = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .arg("approve-source")
            .env_clear()
            .env("APPROVED_RELEASE_SOURCE_SHA", "a".repeat(40))
            .env("APPROVED_RELEASE_BUILDER_SHA", "b".repeat(40))
            .env("GITHUB_SHA", "b".repeat(40))
            .env("REQUESTED_SOURCE_SHA", &requested)
            .env("REQUESTED_BUILDER_SHA", "b".repeat(40))
            .env("GITHUB_OUTPUT", &output)
            .output()
            .unwrap();
        assert_eq!(status.status.success(), requested == "a".repeat(40));
        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            if status.status.success() {
                format!(
                    "source_sha={}\nbuilder_sha={}\n",
                    "a".repeat(40),
                    "b".repeat(40)
                )
            } else {
                String::new()
            }
        );
    }
}

fn release() -> Request {
    Request::parse(&serde_json::json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"build_only":false,"ios_action":"submit","build_number":"42","version":"1.2.3"}).to_string()).unwrap()
}
#[test]
fn all_native_stages_require_full_release_except_resolve_and_builds() {
    let full = release();
    let unsigned =
        Request::parse(r#"{"build_only":true,"ios_action":"skip","build_number":"1"}"#).unwrap();
    for stage in RELEASE_TARGETS {
        full.validate_target(stage).unwrap();
        let allowed = [
            "resolve", "linux", "windows", "macos", "android", "web", "ios",
        ]
        .contains(stage);
        assert_eq!(unsigned.validate_target(stage).is_ok(), allowed, "{stage}");
    }
    assert!(full.validate_target("docker").is_err());
}
#[test]
fn source_and_builder_approval_are_bound_to_requested_and_executing_commits() {
    let env = Environment::from([
        ("APPROVED_RELEASE_SOURCE_SHA".into(), "a".repeat(40)),
        ("APPROVED_RELEASE_BUILDER_SHA".into(), "b".repeat(40)),
        ("GITHUB_SHA".into(), "b".repeat(40)),
    ]);
    validate_approval(&env, &"a".repeat(40), &"b".repeat(40)).unwrap();
    for key in [
        "APPROVED_RELEASE_SOURCE_SHA",
        "APPROVED_RELEASE_BUILDER_SHA",
        "GITHUB_SHA",
    ] {
        let mut bad = env.clone();
        bad.insert(key.into(), "c".repeat(40));
        assert!(validate_approval(&bad, &"a".repeat(40), &"b".repeat(40)).is_err());
    }
}
#[test]
fn normalization_preserves_release_contract_and_denies_partial_release() {
    let full = release();
    let value: serde_json::Value = serde_json::from_str(&full.normalized().unwrap()).unwrap();
    assert!(value.get("verify_target").is_none());
    assert!(value.get("builder_sha").is_none());
    assert_eq!(value["include_selfhost"], true);
    let preview=Request::parse(r#"{"build_only":true,"verify_target":"windows","preview_windows_self_sign":true,"build_number":"1"}"#).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&preview.normalized().unwrap())
            .unwrap()
            .get("preview_windows_self_sign")
            .is_none()
    );
    for patch in [
        serde_json::json!({"include_selfhost":false}),
        serde_json::json!({"ios_action":"skip"}),
        serde_json::json!({"automatic_release":true,"ios_action":"upload"}),
        serde_json::json!({"build_only":"true"}),
    ] {
        let mut raw = serde_json::to_value(&full).unwrap();
        for (k, v) in patch.as_object().unwrap() {
            raw[k] = v.clone();
        }
        assert!(Request::parse(&raw.to_string()).is_err());
    }
}
#[test]
fn private_task_receives_scoped_config_but_never_checkout_credentials_or_command_files() {
    let parent = Environment::from([
        ("SIGNING_CONFIG".into(), "protected".into()),
        ("STORAGE_CONFIG".into(), "protected".into()),
        ("GITHUB_RUN_ID".into(), "42".into()),
        ("GITHUB_OUTPUT".into(), "forbidden".into()),
        ("SOURCE_DEPLOY_KEY".into(), "secret".into()),
        ("SOURCE_KNOWN_HOSTS".into(), "secret".into()),
        ("SOURCE_SUBMODULE_TOKEN".into(), "secret".into()),
        ("SOURCE_SUBMODULE_DEPLOY_KEY_BASE64".into(), "secret".into()),
        ("NODE_OPTIONS".into(), "injection".into()),
    ]);
    let scoped = task_environment(&parent);
    assert_eq!(scoped["SIGNING_CONFIG"], "protected");
    assert_eq!(scoped["STORAGE_CONFIG"], "protected");
    assert_eq!(scoped["GITHUB_RUN_ID"], "42");
    for key in [
        "GITHUB_OUTPUT",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "SOURCE_SUBMODULE_TOKEN",
        "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
        "NODE_OPTIONS",
    ] {
        assert!(!scoped.contains_key(key), "{key}");
    }
}
