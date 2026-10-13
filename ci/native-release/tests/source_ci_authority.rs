//! Offline identity boundary: no source checkout, API, dispatch or release effects.
use serde_json::{Value, json};
use std::{
    fs,
    process::{Command, Output},
};

fn identity() -> Value {
    json!({"source_repository":"omnisolo-llc/omniterm","source_sha":"a".repeat(40),"builder_repository":"omnisolo-llc/omniterm-release","builder_sha":"b".repeat(40),"run_id":"123456789","attempt":"1"})
}
fn request() -> Value {
    json!({"identity":identity(),"source_ref":"refs/heads/main","stage":"rust","shard_index":0,"shard_count":2})
}
fn observed() -> Value {
    json!({
        "execution_repository":{"full_name":"omnisolo-llc/omniterm-release","private":false,"default_branch":"main"},
        "source_repository":{"full_name":"omnisolo-llc/omniterm","private":true,"default_branch":"main"},
        "github_actions":true,"event_name":"workflow_dispatch","execution_ref":"refs/heads/main",
        "workflow_ref":"omnisolo-llc/omniterm-release/.github/workflows/source-ci.yml@refs/heads/main",
        "builder_sha":"b".repeat(40),"run_id":"123456789","attempt":"1",
        "source_ref":"refs/heads/main","source_head_repository":"omnisolo-llc/omniterm","source_state":"main",
        "head_sha":"a".repeat(40),"base_sha":"a".repeat(40),"merge_base_sha":"a".repeat(40),"source_builder_sha":"b".repeat(40),
        "approved_source_sha":"a".repeat(40),"approved_builder_sha":"b".repeat(40),"approved_source_ref":"refs/heads/main","approved_base_sha":"a".repeat(40)
    })
}
fn check_raw(req: &[u8], obs: &[u8]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("request.json"), req).unwrap();
    fs::write(dir.path().join("observation.json"), obs).unwrap();
    Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .args(["check-ci-request", "--request"])
        .arg(dir.path().join("request.json"))
        .arg("--observation")
        .arg(dir.path().join("observation.json"))
        .output()
        .unwrap()
}
fn check(req: &Value, obs: &Value) -> Output {
    check_raw(req.to_string().as_bytes(), obs.to_string().as_bytes())
}
#[test]
fn ci_child_cannot_inherit_source_signing_writer_or_command_file_credentials() {
    use omni_release_launcher::{
        Environment,
        ci_request::{SourceCiRequest, ci_child_environment},
    };
    let mut parent = Environment::from([("PATH".into(), "/usr/bin".into())]);
    let forbidden = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "PRIVATE_RELEASE_TOKEN",
        "SOURCE_METADATA_READ_TOKEN",
        "SOURCE_DEPLOY_KEY",
        "SIGNING_CONFIG",
        "STORAGE_CONFIG",
        "OMNI_PRIVATE_KEY",
        "APP_STORE_CONNECT_API_KEY_BASE64",
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_STEP_SUMMARY",
        "BASH_ENV",
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "LD_PRELOAD",
        "NODE_OPTIONS",
    ];
    for key in forbidden {
        parent.insert(key.into(), "private-canary-value".into());
    }
    let child =
        ci_child_environment(&parent, &SourceCiRequest::parse(&request()).unwrap()).unwrap();
    for key in forbidden {
        assert!(!child.contains_key(key), "credential boundary: {key}");
    }
    assert_eq!(child["GITHUB_REPOSITORY"], "omnisolo-llc/omniterm-release");
    assert_eq!(child["CARGO_BUILD_JOBS"], "2");
    assert_eq!(
        serde_json::from_str::<Value>(&child["SOURCE_CI_REQUEST"]).unwrap(),
        request()
    );
    assert!(
        child
            .values()
            .all(|value| !value.contains("private-canary-value"))
    );
}
#[test]
fn malformed_shards_refs_and_identity_cannot_reach_authorization() {
    use omni_release_launcher::ci_request::SourceCiRequest;
    for (field, value) in [
        ("source_ref", json!("refs/pull/1/merge")),
        ("source_ref", json!("refs/pull/01/head")),
        ("shard_index", json!(2)),
        ("shard_count", json!(0)),
        ("shard_count", json!(65)),
        ("shard_index", json!(false)),
    ] {
        let mut req = request();
        req[field] = value;
        assert!(SourceCiRequest::parse(&req).is_err(), "{field}");
    }
    for field in ["source_sha", "builder_sha"] {
        let mut req = request();
        req["identity"][field] = json!("A".repeat(40));
        assert!(SourceCiRequest::parse(&req).is_err());
    }
}
#[test]
fn exact_ci_identity_is_valid_without_version_or_signing_defaults() {
    let output = check(&request(), &observed());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Source-CI identity is valid; no source acquired or workflow dispatched.\n"
    );
}
#[test]
fn stale_or_missing_protected_pins_cannot_authorize_checkout() {
    for field in [
        "approved_source_sha",
        "approved_builder_sha",
        "approved_base_sha",
        "head_sha",
        "builder_sha",
        "source_builder_sha",
        "base_sha",
        "merge_base_sha",
    ] {
        for value in ["".to_string(), "c".repeat(40)] {
            let mut obs = observed();
            obs[field] = json!(value);
            assert!(!check(&request(), &obs).status.success(), "{field}");
        }
    }
}
#[test]
fn foreign_execution_repository_or_workflow_does_not_borrow_public_privileges() {
    for (field, value) in [
        (
            "execution_repository",
            json!({"full_name":"ql-owo-lp/omniterm","private":true,"default_branch":"main"}),
        ),
        (
            "source_repository",
            json!({"full_name":"omnisolo-llc/omniterm","private":false,"default_branch":"main"}),
        ),
        ("event_name", json!("pull_request_target")),
        ("github_actions", json!(false)),
        (
            "workflow_ref",
            json!("omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main"),
        ),
        ("execution_ref", json!("refs/pull/1/merge")),
        ("attempt", json!("2")),
        ("run_id", json!("999")),
    ] {
        let mut obs = observed();
        obs[field] = value;
        assert!(!check(&request(), &obs).status.success(), "{field}");
    }
}
#[test]
fn private_pr_requires_exact_head_base_and_canonical_head_repository() {
    let mut req = request();
    req["source_ref"] = json!("refs/pull/42/head");
    let mut obs = observed();
    obs["source_ref"] = req["source_ref"].clone();
    obs["approved_source_ref"] = req["source_ref"].clone();
    obs["source_state"] = json!("open");
    for field in ["base_sha", "merge_base_sha", "approved_base_sha"] {
        obs[field] = json!("c".repeat(40));
    }
    assert!(check(&req, &obs).status.success());
    for (field, value) in [
        ("head_sha", json!("d".repeat(40))),
        ("base_sha", json!("d".repeat(40))),
        ("source_head_repository", json!("fork/source")),
        ("source_state", json!("closed")),
        ("approved_source_ref", json!("refs/pull/43/head")),
    ] {
        let mut changed = obs.clone();
        changed[field] = value;
        assert!(!check(&req, &changed).status.success(), "{field}");
    }
}
#[test]
fn request_cannot_change_mode_commands_runner_or_publication_inputs() {
    for field in [
        "version",
        "build_only",
        "publish",
        "command",
        "runner",
        "storage",
        "signing",
    ] {
        let mut req = request();
        req[field] = json!("private-canary-value");
        let output = check(&req, &observed());
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-canary-value"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-canary-value"));
    }
    for stage in [
        "publish",
        "ios-submit",
        "agent-publish",
        "managed-rtc-provider",
        "arbitrary",
    ] {
        let mut req = request();
        req["stage"] = json!(stage);
        assert!(!check(&req, &observed()).status.success());
    }
}
#[test]
fn duplicate_unknown_and_oversized_input_is_rejected_at_every_depth() {
    let req = request().to_string();
    let obs = observed().to_string();
    let duplicate = req.replacen("{", "{\"stage\":\"publish\",", 1);
    assert!(
        !check_raw(duplicate.as_bytes(), obs.as_bytes())
            .status
            .success()
    );
    let nested = req.replacen(
        "\"source_sha\":",
        "\"source_sha\":\"bad\",\"source_sha\":",
        1,
    );
    assert!(
        !check_raw(nested.as_bytes(), obs.as_bytes())
            .status
            .success()
    );
    assert!(
        !check_raw(&vec![b' '; 16_385], obs.as_bytes())
            .status
            .success()
    );
    let mut extra = observed();
    extra["approval_bypass"] = json!(true);
    assert!(!check(&request(), &extra).status.success());
}
