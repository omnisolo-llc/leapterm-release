//! Current launcher/workflow regressions only. These assertions do not stand
//! in for a genuine signed Plan, retained archive, provider, or release result.
use leap_release_launcher::{Environment, launch};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn environment(target: &str) -> Environment {
    Environment::from([
        ("GITHUB_ACTIONS".into(), "true".into()),
        ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
        (
            "GITHUB_REPOSITORY".into(),
            "omnisolo-llc/leapterm-release".into(),
        ),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        (
            "GITHUB_WORKFLOW_REF".into(),
            "omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main".into(),
        ),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("GITHUB_RUN_ID".into(), "42".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
        ("SOURCE_REPOSITORY".into(), "example-org/private-source".into()),
        ("SOURCE_BRANCH".into(), "main".into()),
        ("SOURCE_DEPLOY_KEY".into(), "owned fixture".into()),
        ("SOURCE_KNOWN_HOSTS".into(), "owned fixture".into()),
        (
            "LEAPTERM_VPN_PROVIDER_PUBLIC_KEY".into(),
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [1u8; 32]),
        ),
        ("RELEASE_TARGET".into(), target.into()),
        (
            "RELEASE_REQUEST".into(),
            json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"version":"1.2.3","build_number":"42","build_only":false,"ios_action":"submit","release_route":"option1"}).to_string(),
        ),
        ("RESOLVED_SOURCE_SHA".into(), "a".repeat(40)),
        ("BUILD_CONFIG".into(), json!({"LEAP_ENABLE_VPN":"true"}).to_string()),
        ("STORAGE_CONFIG".into(), "{}".into()),
    ])
}

#[test]
fn launcher_exposes_complete_archive_retention_and_independent_readback_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_leap-release-launcher"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "prepare-private-final-archive",
        "verify-private-final-archive",
    ] {
        assert!(help.contains(command), "Missing archive command: {command}");
    }
}

#[test]
fn archive_commands_are_confined_to_the_publish_configuration() {
    assert!(launch::validate_configuration(&environment("publish"), "prepare-publication").is_ok());
    for command in [
        "prepare-private-final-archive",
        "verify-private-final-archive",
    ] {
        for target in ["linux", "windows", "macos", "android", "ios", "web"] {
            assert_eq!(
                launch::validate_configuration(&environment(target), command).err(),
                Some("Native workflow target mismatch"),
                "{command}/{target}"
            );
        }
        assert!(launch::validate_configuration(&environment("publish"), command).is_ok());
    }
}

#[test]
fn public_writer_requires_ordered_native_archive_and_independent_readback_outputs() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    let yaml: serde_yaml::Value = serde_yaml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let workflow: Value = serde_json::to_value(yaml).unwrap();
    let publish = &workflow["jobs"]["publish"];
    let steps = publish["steps"].as_array().unwrap();
    let prepare = steps
        .iter()
        .position(|step| step["id"] == "publication_candidates")
        .unwrap();
    let retain = steps
        .iter()
        .position(|step| step["id"] == "private_final_archive")
        .expect("Missing complete archive retention step");
    let readback = steps
        .iter()
        .position(|step| step["id"] == "private_final_archive_readback")
        .expect("Missing independent archive readback step");
    let writer = steps
        .iter()
        .position(|step| step["run"] == "bash ci/native-release/run.sh publish-candidates")
        .unwrap();
    assert!(prepare < retain && retain < readback && readback < writer);
    assert_eq!(
        steps[retain]["run"],
        "bash ci/native-release/run.sh prepare-private-final-archive"
    );
    assert_eq!(
        steps[readback]["run"],
        "bash ci/native-release/run.sh verify-private-final-archive"
    );
    for index in [retain, readback] {
        assert_eq!(steps[index]["env"]["RELEASE_TARGET"], "publish");
        assert_eq!(
            steps[index]["env"]["APPROVED_NATIVE_VERIFIER_SHA256"],
            "${{ steps.publication_candidates.outputs.native_verifier_sha256 }}"
        );
        assert_eq!(
            steps[index]["env"]["APPROVED_PUBLICATION_PLAN_SHA256"],
            "${{ steps.publication_candidates.outputs.publication_plan_sha256 }}"
        );
        for key in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "PRIVATE_RELEASE_TOKEN",
            "SIGNING_CONFIG",
        ] {
            assert!(
                steps[index]["env"].get(key).is_none(),
                "Archive child received {key}"
            );
        }
    }
    assert_eq!(
        steps[retain]["env"]["PRIVATE_FINAL_ARCHIVE_INPUTS_FILE"],
        "${{ vars.PRIVATE_FINAL_ARCHIVE_INPUTS_FILE }}"
    );
    assert!(
        steps[readback]["env"]
            .get("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE")
            .is_none()
    );
    assert_eq!(
        steps[writer]["env"]["APPROVED_PRIVATE_ARCHIVE_PROOF_SHA256"],
        "${{ steps.private_final_archive_readback.outputs.private_archive_proof_sha256 }}"
    );
    assert_eq!(
        steps[writer]["env"]["GH_TOKEN"],
        "${{ secrets.PRIVATE_RELEASE_TOKEN }}"
    );
    let node = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/setup-node@"))
        })
        .unwrap();
    assert_eq!(node["with"]["node-version"], "24.21.0");
    assert_eq!(node["with"]["package-manager-cache"], false);
    let automatic = steps
        .iter()
        .find(|step| step["name"] == "Auto-promote candidates to pre-release store tracks")
        .unwrap();
    assert_eq!(automatic["if"], "${{ inputs.auto_promote }}");
    let script = automatic["run"].as_str().unwrap();
    assert!(script.contains("promote-release.yml"));
    assert!(script.contains("-f publish_github_release=false"));
    assert!(script.contains("IOS_ACTION=\"testflight\""));
    assert!(script.contains("MACOS_ACTION=\"testflight\""));
    assert!(script.contains("ANDROID_ACTION=\"alpha\""));
    assert!(script.contains("-f ios_store_action=\"${IOS_ACTION}\""));
    assert!(script.contains("-f macos_store_action=\"${MACOS_ACTION}\""));
    assert!(script.contains("-f android_store_action=\"${ANDROID_ACTION}\""));
}
