use serde_json::json;
use std::{fs, process::Command};

#[test]
fn automatic_request_selection_accepts_main_or_sha_without_manual_approval() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("outputs");
    for (source, builder, event, accepted) in [
        (String::new(), String::new(), "workflow_dispatch", true),
        ("a".repeat(40), "b".repeat(40), "workflow_dispatch", true),
        (
            "bad\nsource_sha=evil".into(),
            String::new(),
            "workflow_dispatch",
            false,
        ),
        ("a".repeat(40), "c".repeat(40), "workflow_dispatch", false),
        (String::new(), String::new(), "pull_request", false),
    ] {
        fs::write(&output, "").unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .arg("validate-request")
            .env_clear()
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_EVENT_NAME", event)
            .env("GITHUB_REPOSITORY", "omnisolo-llc/omniterm-release")
            .env("GITHUB_REF", "refs/heads/main")
            .env("GITHUB_WORKFLOW_REF", "omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main")
            .env("GITHUB_SHA", "b".repeat(40))
            .env("GITHUB_RUN_ID", "42")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("SOURCE_REPOSITORY", "omnisolo-llc/omniterm")
            .env("SOURCE_BRANCH", "main")
            .env("GITHUB_OUTPUT", &output)
            .env("RELEASE_REQUEST", json!({"source_sha":source,"builder_sha":builder,"build_only":false,"version":"0.1.1","build_number":"3","ios_action":"upload"}).to_string())
            .output().unwrap();
        assert_eq!(
            result.status.success(),
            accepted,
            "automatic request selection"
        );
        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            if accepted {
                format!("source_sha={source}\nbuilder_sha={}\n", "b".repeat(40))
            } else {
                String::new()
            }
        );
    }
}

#[test]
fn release_workflow_has_no_manual_sha_variable_dependency() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
    assert!(!workflow.contains("APPROVED_RELEASE_SOURCE_SHA"));
    assert!(!workflow.contains("APPROVED_RELEASE_BUILDER_SHA"));
    assert!(workflow.contains("bash ci/native-release/run.sh validate-request"));
}
