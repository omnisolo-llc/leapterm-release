use leap_release_launcher::{
    Environment,
    ci_request::{BUILDER_REPOSITORY, CI_STAGES, PipelineIdentity, SourceCiRequest},
    pre_release_ci::{
        NIGHTLY_WORKFLOW, build_stage_request, gate_fingerprint, require_nightly_origin,
        verify_nightly_stage_receipt,
    },
    runner_policy, source_api,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path};

fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn valid_nightly_env(event: &str) -> Environment {
    [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", event),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_REPOSITORY", BUILDER_REPOSITORY),
        ("GITHUB_WORKFLOW_REF", NIGHTLY_WORKFLOW),
        ("GITHUB_SHA", &"b".repeat(40)),
        ("GITHUB_RUN_ID", "45001234567"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("SOURCE_REPOSITORY", "example-org/private-source"),
        ("SOURCE_BRANCH", "main"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn sample_request(stage: &str) -> SourceCiRequest {
    SourceCiRequest {
        identity: PipelineIdentity {
            source_repository: "example-org/private-source".into(),
            source_sha: "a".repeat(40),
            builder_repository: BUILDER_REPOSITORY.into(),
            builder_sha: "b".repeat(40),
            run_id: "45001234567".into(),
            attempt: "1".into(),
        },
        source_ref: "refs/heads/main".into(),
        stage: stage.into(),
        shard_index: 0,
        shard_count: 1,
    }
}

fn sample_passing_receipt(request: &SourceCiRequest, catalog_sha256: &str) -> Value {
    let suite_id = format!("{}:0:unit", request.stage);
    let case_id = format!("{suite_id}::case-1");
    let cases = json!([case_id]);
    let case_digest = source_api::json_digest(&cases).unwrap();
    let input_hash = "c".repeat(64);
    let inputs = json!({"Cargo.toml": input_hash});
    json!({
        "schema": "leapterm.source-ci.stage.v1",
        "request": request,
        "catalog_sha256": catalog_sha256,
        "inputs": inputs,
        "suites": [{
            "id": suite_id,
            "kind": "node",
            "command_sha256": "d".repeat(64),
            "input_sha256": inputs,
            "case_ids": cases,
            "case_ids_sha256": case_digest,
            "expected": 1,
            "registered": 1,
            "executed": 1,
            "passed": 1,
            "failed": 0,
            "skipped": 0,
            "status": "passed",
        }],
        "case_ids_sha256": case_digest,
        "expected": 1,
        "registered": 1,
        "executed": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "status": "passed",
    })
}

#[test]
fn nightly_origin_accepts_only_main_schedule_or_dispatch() {
    assert!(require_nightly_origin(&valid_nightly_env("schedule")).is_ok());
    assert!(require_nightly_origin(&valid_nightly_env("workflow_dispatch")).is_ok());

    for (key, bad_value) in [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_REPOSITORY", "other-org/leapterm-release"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main",
        ),
        ("SOURCE_BRANCH", "dev"),
        ("GITHUB_ACTIONS", "false"),
    ] {
        let mut env = valid_nightly_env("schedule");
        env.insert(key.into(), bad_value.into());
        assert!(
            require_nightly_origin(&env).is_err(),
            "expected rejection for {key}={bad_value}"
        );
    }
}

#[test]
fn gate_fingerprint_is_deterministic_24_hex_and_rejects_malformed_inputs() {
    let fp1 = gate_fingerprint(&"a".repeat(40), &"b".repeat(40), &"c".repeat(64)).unwrap();
    let fp2 = gate_fingerprint(&"a".repeat(40), &"b".repeat(40), &"c".repeat(64)).unwrap();
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 24);
    assert!(fp1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

    let fp_diff = gate_fingerprint(&"d".repeat(40), &"b".repeat(40), &"c".repeat(64)).unwrap();
    assert_ne!(fp1, fp_diff);

    assert!(gate_fingerprint("short", &"b".repeat(40), &"c".repeat(64)).is_err());
    assert!(gate_fingerprint(&"a".repeat(40), "short", &"c".repeat(64)).is_err());
    assert!(gate_fingerprint(&"a".repeat(40), &"b".repeat(40), "short").is_err());
}

#[test]
fn build_stage_request_requires_valid_stage_sha_and_catalog() {
    let mut env = valid_nightly_env("schedule");
    env.insert("PRE_RELEASE_CI_STAGE".into(), "worker".into());
    env.insert("RESOLVED_SOURCE_SHA".into(), "a".repeat(40));
    env.insert("SOURCE_CI_CATALOG_SHA256".into(), "e".repeat(64));
    let (request, catalog) = build_stage_request(&env).unwrap();
    assert_eq!(request.stage, "worker");
    assert_eq!(request.source_ref, "refs/heads/main");
    assert_eq!(catalog, "e".repeat(64));

    env.insert("PRE_RELEASE_CI_STAGE".into(), "unknown-stage".into());
    assert!(build_stage_request(&env).is_err());
}

#[test]
fn verify_nightly_stage_receipt_is_fail_closed_on_failures_skips_or_catalog_drift() {
    let temp = tempfile::tempdir().unwrap();
    let receipt_path = temp.path().join("source-ci-stage.json");
    let request = sample_request("worker");
    let catalog = "f".repeat(64);

    let good = sample_passing_receipt(&request, &catalog);
    fs::write(&receipt_path, serde_json::to_vec(&good).unwrap()).unwrap();
    let summary = verify_nightly_stage_receipt(&receipt_path, &request, &catalog).unwrap();
    assert_eq!(summary["passed"], 1);
    assert_eq!(summary["failed"], 0);
    assert_eq!(summary["skipped"], 0);

    // Wrong catalog digest must fail closed.
    assert!(verify_nightly_stage_receipt(&receipt_path, &request, &"0".repeat(64)).is_err());

    // Any failed or skipped case must fail closed.
    let mut with_skip = good.clone();
    with_skip["skipped"] = json!(1);
    with_skip["passed"] = json!(0);
    fs::write(&receipt_path, serde_json::to_vec(&with_skip).unwrap()).unwrap();
    assert!(verify_nightly_stage_receipt(&receipt_path, &request, &catalog).is_err());

    let mut with_failure = good.clone();
    with_failure["status"] = json!("failed");
    with_failure["failed"] = json!(1);
    with_failure["passed"] = json!(0);
    fs::write(&receipt_path, serde_json::to_vec(&with_failure).unwrap()).unwrap();
    assert!(verify_nightly_stage_receipt(&receipt_path, &request, &catalog).is_err());

    // Wrong filename must fail closed.
    let wrong_name = temp.path().join("other.json");
    fs::write(&wrong_name, serde_json::to_vec(&good).unwrap()).unwrap();
    assert!(verify_nightly_stage_receipt(&wrong_name, &request, &catalog).is_err());
}

#[test]
fn verify_nightly_stage_receipt_accepts_large_flutter_vm_receipt_and_rejects_oversize() {
    let temp = tempfile::tempdir().unwrap();
    let receipt_path = temp.path().join("source-ci-stage.json");
    let request = sample_request("flutter-vm");
    let catalog = "f".repeat(64);
    let suite_id = "flutter-vm:flutter-quality-and-tests:0000";
    let pad = "a".repeat(96);
    let mut case_ids: Vec<String> = (0..10_000)
        .map(|i| {
            format!(
                "{suite_id}::test/suite_{:04}_test.dart::case_{i:05}_{pad}",
                i / 8
            )
        })
        .collect();
    case_ids.sort();
    let case_digest = source_api::json_digest(&json!(case_ids)).unwrap();
    let mut input_map = serde_json::Map::new();
    let input_hash = "c".repeat(64);
    for i in 0..4_500 {
        input_map.insert(
            format!("app/test/suite_{i:04}_test.dart"),
            json!(input_hash),
        );
    }
    let inputs = Value::Object(input_map);
    let large = json!({
        "schema": "leapterm.source-ci.stage.v1",
        "request": request,
        "catalog_sha256": catalog,
        "inputs": inputs,
        "suites": [{
            "id": suite_id,
            "kind": "flutter",
            "command_sha256": "d".repeat(64),
            "input_sha256": inputs,
            "case_ids": case_ids,
            "case_ids_sha256": case_digest,
            "expected": case_ids.len(),
            "registered": case_ids.len(),
            "executed": case_ids.len(),
            "passed": case_ids.len(),
            "failed": 0,
            "skipped": 0,
            "status": "passed",
        }],
        "case_ids_sha256": case_digest,
        "expected": case_ids.len(),
        "registered": case_ids.len(),
        "executed": case_ids.len(),
        "passed": case_ids.len(),
        "failed": 0,
        "skipped": 0,
        "status": "passed",
    });
    let encoded = serde_json::to_vec(&large).unwrap();
    assert!(
        encoded.len() > 1_048_576,
        "receipt fixture must exceed 1 MiB"
    );
    fs::write(&receipt_path, &encoded).unwrap();
    let summary = verify_nightly_stage_receipt(&receipt_path, &request, &catalog).unwrap();
    assert_eq!(summary["passed"], 10_000);

    // Receipts exceeding MAX_RECEIPT must still fail closed.
    let mut oversize = vec![b' '; source_api::MAX_RECEIPT + 1];
    oversize[0] = b'{';
    oversize[source_api::MAX_RECEIPT] = b'}';
    fs::write(&receipt_path, &oversize).unwrap();
    assert!(verify_nightly_stage_receipt(&receipt_path, &request, &catalog).is_err());
}

#[test]
fn nightly_workflow_obeys_runner_policy_covers_all_13_stages_and_is_fail_closed() {
    let repo = repository();
    let workflow_path = repo.join(".github/workflows/nightly-testflight.yml");
    let policy_path = repo.join("ci/standard-runner-policy.json");
    let policy = leap_release_launcher::json::parse(&fs::read(&policy_path).unwrap()).unwrap();
    let audit = runner_policy::audit_workflows(&workflow_path, &policy).unwrap();
    assert_eq!(
        audit["findings"].as_array().unwrap().len(),
        0,
        "nightly-testflight.yml violated standard-runner-policy: {audit}"
    );

    let raw = fs::read_to_string(&workflow_path).unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();

    // No skip_tests input bypass allowed.
    let inputs = parsed["on"]["workflow_dispatch"]["inputs"]
        .as_mapping()
        .unwrap();
    assert!(
        inputs.keys().all(|k| !k
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("skip")),
        "nightly-testflight.yml must never expose a skip_tests bypass input"
    );

    // No continue-on-error or workflow-level env secrets.
    assert!(parsed["env"].is_null());
    assert!(!raw.contains("continue-on-error"));

    // Verify all 13 CI_STAGES are wired into source_ci_gate matrix.
    let stages: BTreeSet<&str> = parsed["jobs"]["source_ci_gate"]["strategy"]["matrix"]["stage"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let expected: BTreeSet<&str> = CI_STAGES.into_iter().collect();
    assert_eq!(stages, expected);

    // Verify source_ci_gate retains encrypted diagnostics privately on failure.
    let gate_steps = parsed["jobs"]["source_ci_gate"]["steps"]
        .as_sequence()
        .unwrap();
    assert!(
        gate_steps
            .iter()
            .any(|s| s["run"].as_str() == Some("bash ci/native-release/run.sh pre-release-ci"))
    );
    assert!(gate_steps.iter().any(|s| {
        s["run"].as_str() == Some("bash ci/native-release/run.sh retain-nightly-diagnostics")
            && s["if"].as_str() == Some("${{ failure() }}")
    }));

    // Verify dispatch_nightly requires source_ci_gate success (or verified reuse) and pins REQUIRE_SOURCE_CI_GATE=true.
    let dispatch = &parsed["jobs"]["dispatch_nightly"];
    let dispatch_if = dispatch["if"].as_str().unwrap();
    assert!(dispatch_if.contains("needs.source_ci_gate.result == 'success'"));
    assert!(dispatch_if.contains("needs.resolve_nightly.outputs.already_verified == 'true'"));
    let dispatch_step = dispatch["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|s| s["run"].as_str() == Some("node ci/nightly-testflight-dispatch.mjs"))
        .unwrap();
    assert_eq!(
        dispatch_step["env"]["REQUIRE_SOURCE_CI_GATE"].as_str(),
        Some("true")
    );
    assert_eq!(
        dispatch_step["env"]["VERIFIED_SOURCE_SHA"].as_str(),
        Some("${{ needs.resolve_nightly.outputs.source_sha }}")
    );
}
