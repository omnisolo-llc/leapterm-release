//! Actual files and CLI observations; no workflow is submitted by these tests.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

const RUNNERS: [&str; 6] = [
    "ubuntu-24.04",
    "ubuntu-24.04-arm",
    "windows-2025",
    "windows-11-arm",
    "macos-15-intel",
    "macos-26",
];
fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    fs::write(dir.path().join("policy.json"), json!({"schema":1,"repository":"omnisolo-llc/omniterm-release","runners":RUNNERS,"prohibit_actions_storage":true}).to_string()).unwrap();
    dir
}
fn put(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}
fn audit(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .args(["audit-runners", "--workflows"])
        .arg(root.join(".github/workflows"))
        .arg("--policy")
        .arg(root.join("policy.json"))
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_REPOSITORY")
        .output()
        .unwrap()
}
fn codes(output: &Output) -> Vec<String> {
    let value: Value = serde_json::from_slice(&output.stdout)
        .expect("audit must return bounded findings, not raw workflow data");
    value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_owned())
        .collect()
}
fn rejected(root: &Path, code: &str) {
    let output = audit(root);
    assert!(!output.status.success(), "unsafe workflow was accepted");
    assert!(
        codes(&output).iter().any(|c| c == code),
        "missing finding {code}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn public_candidates_workflow() -> Value {
    let mut identity = json!({
        "RELEASE_REQUEST": "${{ toJSON(inputs) }}",
        "RESOLVED_SOURCE_SHA": "${{ needs.resolve.outputs.source_sha }}",
        "RESOLVED_VERSION": "${{ needs.resolve.outputs.version }}",
        "RESOLVED_BUILD_NUMBER": "${{ needs.resolve.outputs.build_number }}"
    });
    for key in [
        "SOURCE_REPOSITORY",
        "SOURCE_BRANCH",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "SOURCE_SUBMODULE_TOKEN",
        "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
        "DIAGNOSTICS_PUBLIC_KEY",
        "BUILD_CONFIG",
        "STORAGE_CONFIG",
    ] {
        identity[key] = json!(format!("${{{{ secrets.{key} }}}}"));
    }
    let mut producer = identity.clone();
    producer["RELEASE_TARGET"] = json!("${{ matrix.target }}");
    let mut preflight = identity;
    preflight["RELEASE_TARGET"] = json!("publish");
    preflight["INPUT_PUBLIC_CANDIDATES_DIR"] =
        json!("${{ github.workspace }}/release-public-candidates");
    let mut signer = preflight.clone();
    signer["BUILD_CONFIG"] = json!("${{ secrets.BUILD_CONFIG }}");
    signer["STORAGE_CONFIG"] = json!("${{ secrets.STORAGE_CONFIG }}");
    signer["SIGNING_CONFIG"] = json!("${{ secrets.PACKAGE_SIGNING_CONFIG }}");
    json!({"jobs": {
        "verify": {
            "if": "${{ !cancelled() && needs.resolve.result == 'success' && github.repository == 'omnisolo-llc/omniterm-release' && github.ref == 'refs/heads/main' }}",
            "needs": "resolve",
            "continue-on-error": true,
            "environment": "downloads",
            "permissions": {"contents": "read"},
            "runs-on": "ubuntu-24.04",
            "strategy": {"matrix": {"target": ["linux"]}},
            "steps": [
                {"id": "public_candidates", "run": "bash ci/native-release/run.sh verify-build", "env": producer},
                {"id": "public_candidates_upload",
                 "if": "${{ success() && matrix.target != 'ios' && !inputs.build_only && inputs.release_route == 'option1' }}",
                 "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                 "with": {"name": "public-candidates-${{ matrix.target }}",
                     "path": "${{ runner.temp }}/reviewed-public-candidates/${{ matrix.target }}",
                     "if-no-files-found": "error", "retention-days": 7, "compression-level": 0}}
            ]
        },
        "publish": {
            "if": "${{ !cancelled() && !inputs.build_only && github.repository == 'omnisolo-llc/omniterm-release' && github.ref == 'refs/heads/main' && needs.resolve.result == 'success' && inputs.release_route == 'option1' }}",
            "needs": ["resolve", "verify"],
            "environment": "public-release",
            "permissions": {"contents": "write"},
            "runs-on": "ubuntu-24.04",
            "steps": [
                {"id": "public_candidates_download",
                 "uses": "actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16",
                 "with": {"pattern": "public-candidates-*", "path": "release-public-candidates", "merge-multiple": false}},
                {"id": "publication_candidates", "run": "bash ci/native-release/run.sh prepare-publication", "env": preflight}
            ]
        },
        "option1_signatures": {
            "if": "${{ !cancelled() && !inputs.build_only && inputs.release_route == 'option1' && github.repository == 'omnisolo-llc/omniterm-release' && github.ref == 'refs/heads/main' && needs.resolve.result == 'success' }}",
            "needs": ["resolve", "verify"],
            "environment": "package-signing",
            "permissions": {"contents": "read"},
            "runs-on": "ubuntu-24.04",
            "steps": [
                {"id": "protected_candidates_download",
                 "uses": "actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16",
                 "with": {"pattern": "public-candidates-*", "path": "release-public-candidates", "merge-multiple": false}},
                {"id": "public_candidate_signatures", "run": "bash ci/native-release/run.sh sign-public-candidates", "env": signer}
            ]
        }
    }})
}

fn put_candidate_workflow(root: &Path, value: &Value) {
    put(
        root,
        ".github/workflows/release.yml",
        &serde_yaml::to_string(value).unwrap(),
    );
}

fn candidate_rejected(value: &Value) {
    let dir = fixture();
    put_candidate_workflow(dir.path(), value);
    rejected(dir.path(), "actions_storage_forbidden");
}

#[test]
fn direct_public_candidate_pair_is_explicitly_admitted_without_general_storage() {
    for sdk in [false, true] {
        let dir = fixture();
        let mut doc = public_candidates_workflow();
        doc["defaults"] = json!({"run": {"shell": "bash"}});
        if sdk {
            doc["jobs"]["verify"]["if"] = json!(
                "${{ !cancelled() && needs.resolve.result == 'success' && (needs.windows_sdk.result == 'success' || (needs.windows_sdk.result == 'skipped' && inputs.verify_target != 'all' && inputs.verify_target != 'windows')) && github.repository == 'omnisolo-llc/omniterm-release' && github.ref == 'refs/heads/main' }}"
            );
            doc["jobs"]["verify"]["needs"] = json!(["resolve", "windows_sdk"]);
            doc["jobs"]["verify"]["permissions"]["id-token"] = json!("write");
            doc["jobs"]["verify"]["steps"][0]["env"]["OMNI_WINDOWS_ARTIFACT_SIGNING_DLIB"] = json!(
                "${{ !inputs.build_only && matrix.target == 'windows' && format('{0}/artifact-signing/package/bin/x64/Azure.CodeSigning.Dlib.dll', runner.temp) || '' }}"
            );
            let mut env = doc["jobs"]["verify"]["steps"][0]["env"].clone();
            for key in [
                "DIAGNOSTICS_PUBLIC_KEY",
                "BUILD_CONFIG",
                "OMNI_WINDOWS_ARTIFACT_SIGNING_DLIB",
            ] {
                env.as_object_mut().unwrap().remove(key);
            }
            env["RELEASE_ARTIFACT_KIND"] = json!("evaluation");
            env["RELEASE_ARTIFACT_SCOPE"] = json!("verify-${{ matrix.target }}");
            env["STORAGE_CONFIG"] = json!("${{ secrets.STORAGE_CONFIG }}");
            doc["jobs"]["verify"]["steps"].as_array_mut().unwrap().insert(1, json!({
                "name": "Retain recipient-encrypted Windows evaluation privately",
                "if": "${{ success() && inputs.preview_windows_self_sign && matrix.target == 'windows' }}",
                "run": "bash ci/native-release/run.sh retain-artifacts", "env": env
            }));
        }
        put_candidate_workflow(dir.path(), &doc);
        let output = audit(dir.path());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["findings"], json!([]));
        assert_eq!(
            report["public_candidate_exchanges"],
            json!([
                {"workflow": "release.yml", "job": "option1_signatures", "kind": "download"},
                {"workflow": "release.yml", "job": "publish", "kind": "download"},
                {"workflow": "release.yml", "job": "verify", "kind": "upload"}
            ])
        );
    }
    for omitted in [
        "SOURCE_SUBMODULE_TOKEN",
        "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
    ] {
        let dir = fixture();
        let mut doc = public_candidates_workflow();
        for (job, index) in [("verify", 0), ("publish", 1), ("option1_signatures", 1)] {
            doc["jobs"][job]["steps"][index]["env"]
                .as_object_mut()
                .unwrap()
                .remove(omitted);
        }
        put_candidate_workflow(dir.path(), &doc);
        let output = audit(dir.path());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(codes(&output).is_empty());
    }
}

#[test]
fn native_candidate_roles_reject_omitted_source_and_preparation_configuration() {
    for (job, index) in [("verify", 0), ("publish", 1), ("option1_signatures", 1)] {
        for key in [
            "SOURCE_REPOSITORY",
            "SOURCE_BRANCH",
            "SOURCE_DEPLOY_KEY",
            "SOURCE_KNOWN_HOSTS",
            "DIAGNOSTICS_PUBLIC_KEY",
            "BUILD_CONFIG",
            "STORAGE_CONFIG",
        ] {
            let mut doc = public_candidates_workflow();
            doc["jobs"][job]["steps"][index]["env"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            candidate_rejected(&doc);
        }
    }
}

#[test]
fn public_candidate_upload_rejects_other_payloads_pins_and_conditions() {
    for (key, value) in [
        ("name", json!("diagnostics")),
        ("path", json!("release-work/outputs/*")),
        ("path", json!("${{ runner.temp }}/windows-preview/")),
        (
            "path",
            json!("${{ runner.temp }}/encrypted-diagnostics/diagnostics.sealed"),
        ),
        (
            "path",
            json!("${{ runner.temp }}/reviewed-public-candidates/../private"),
        ),
        ("if-no-files-found", json!("ignore")),
        ("retention-days", json!(30)),
        ("compression-level", json!(9)),
        ("include-hidden-files", json!(true)),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["verify"]["steps"][1]["with"][key] = value;
        candidate_rejected(&doc);
    }
    for (key, value) in [
        (
            "uses",
            json!("actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ),
        ("if", json!("${{ !cancelled() }}")),
        ("id", json!("ordinary_upload")),
        ("env", json!({"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"})),
        ("run", json!("copy private source")),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["verify"]["steps"][1][key] = value;
        candidate_rejected(&doc);
    }
}

#[test]
fn public_candidate_download_cannot_select_other_runs_or_merge_targets() {
    for (key, value) in [
        ("pattern", json!("*")),
        ("path", json!("release-public-candidates/../private")),
        ("merge-multiple", json!(true)),
        ("run-id", json!("previous-run")),
        ("repository", json!("other/repository")),
        (
            "github-token",
            json!("${{ secrets.PRIVATE_RELEASE_TOKEN }}"),
        ),
        ("name", json!("private-diagnostics")),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["publish"]["steps"][0]["with"][key] = value;
        candidate_rejected(&doc);
    }
    let mut doc = public_candidates_workflow();
    doc["jobs"]["publish"]["steps"][0]["uses"] =
        json!("actions/download-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    candidate_rejected(&doc);
}

#[test]
fn public_candidate_exchange_requires_canonical_job_routing_and_step_scope() {
    for (job, key, value) in [
        ("verify", "continue-on-error", json!(false)),
        ("verify", "if", json!("${{ always() }}")),
        ("verify", "needs", json!(["other"])),
        (
            "publish",
            "if",
            json!("${{ needs.resolve.result == 'success' }}"),
        ),
        ("publish", "needs", json!(["resolve", "installation"])),
        ("publish", "environment", json!("downloads")),
        (
            "publish",
            "env",
            json!({"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}),
        ),
        (
            "verify",
            "defaults",
            json!({"run": {"shell": "unreviewed shell"}}),
        ),
        ("publish", "container", json!({"image": "unreviewed-image"})),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"][job][key] = value;
        candidate_rejected(&doc);
    }
    let mut doc = public_candidates_workflow();
    doc["env"] = json!({"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"});
    candidate_rejected(&doc);
    let mut doc = public_candidates_workflow();
    doc["defaults"] = json!({"run": {"shell": "unreviewed shell"}});
    candidate_rejected(&doc);
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        &serde_yaml::to_string(&public_candidates_workflow()).unwrap(),
    );
    rejected(dir.path(), "actions_storage_forbidden");
}

#[test]
fn public_candidate_exchange_requires_bound_native_staging_and_preflight() {
    for (job, index, key, value) in [
        ("verify", 0, "run", json!("copy raw private artifacts")),
        ("verify", 0, "id", json!("foreign_producer")),
        (
            "publish",
            1,
            "run",
            json!("bash ci/native-release/run.sh run"),
        ),
        ("publish", 1, "id", json!("foreign_preflight")),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"][job]["steps"][index][key] = value;
        candidate_rejected(&doc);
    }
    for (job, index, key, value) in [
        ("verify", 0, "RESOLVED_SOURCE_SHA", json!("foreign-source")),
        ("verify", 0, "RELEASE_TARGET", json!("windows")),
        (
            "publish",
            1,
            "INPUT_PUBLIC_CANDIDATES_DIR",
            json!("${{ github.workspace }}/private"),
        ),
        (
            "publish",
            1,
            "GH_TOKEN",
            json!("${{ secrets.GITHUB_TOKEN }}"),
        ),
        (
            "publish",
            1,
            "PRIVATE_RELEASE_TOKEN",
            json!("${{ secrets.PRIVATE_RELEASE_TOKEN }}"),
        ),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"][job]["steps"][index]["env"][key] = value;
        candidate_rejected(&doc);
    }
    let mut doc = public_candidates_workflow();
    doc["jobs"]["verify"]["steps"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({"run": "rewrite staged files"}));
    candidate_rejected(&doc);
    let mut doc = public_candidates_workflow();
    doc["jobs"]["publish"]["steps"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    candidate_rejected(&doc);
}

#[test]
fn public_candidate_exchange_cannot_be_nested_in_composites_or_reusable_workflows() {
    let dir = fixture();
    let mut doc = public_candidates_workflow();
    let upload = doc["jobs"]["verify"]["steps"][1].take();
    doc["jobs"]["verify"]["steps"][1] = json!({"uses": "./ci/candidates"});
    put_candidate_workflow(dir.path(), &doc);
    put(
        dir.path(),
        "ci/candidates/action.yml",
        &serde_yaml::to_string(&json!({"runs": {"using": "composite", "steps": [upload]}}))
            .unwrap(),
    );
    rejected(dir.path(), "actions_storage_forbidden");

    for parent in ["aa-parent", "zz-parent"] {
        let dir = fixture();
        put_candidate_workflow(dir.path(), &public_candidates_workflow());
        put(
            dir.path(),
            &format!(".github/workflows/{parent}.yml"),
            "jobs:\n  call:\n    uses: ./.github/workflows/release.yml\n",
        );
        rejected(dir.path(), "actions_storage_forbidden");
    }
}

#[test]
fn public_candidate_exception_does_not_accept_a_relaxed_policy() {
    let dir = fixture();
    put_candidate_workflow(dir.path(), &public_candidates_workflow());
    let mut policy: Value =
        serde_json::from_slice(&fs::read(dir.path().join("policy.json")).unwrap()).unwrap();
    policy["prohibit_actions_storage"] = json!(false);
    fs::write(dir.path().join("policy.json"), policy.to_string()).unwrap();
    rejected(dir.path(), "policy_invalid");
}

#[test]
fn public_candidate_exchange_rejects_duplicate_declarations() {
    for (job, index) in [("verify", 1), ("publish", 0), ("option1_signatures", 0)] {
        let mut doc = public_candidates_workflow();
        let step = doc["jobs"][job]["steps"][index].clone();
        doc["jobs"][job]["steps"].as_array_mut().unwrap().push(step);
        candidate_rejected(&doc);
        doc["jobs"][job]["steps"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["name"] = json!("second declaration");
        candidate_rejected(&doc);
    }
}

#[test]
fn protected_candidate_download_requires_original_signing_environment_and_exact_identity() {
    for (key, value) in [
        ("environment", json!("public-release")),
        ("permissions", json!({"contents": "write"})),
        (
            "permissions",
            json!({"contents": "read", "id-token": "write"}),
        ),
        ("if", json!("${{ !cancelled() }}")),
        ("needs", json!(["resolve", "verify", "installation"])),
        ("continue-on-error", json!(true)),
        (
            "env",
            json!({"SIGNING_CONFIG": "${{ secrets.PACKAGE_SIGNING_CONFIG }}"}),
        ),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["option1_signatures"][key] = value;
        candidate_rejected(&doc);
    }
    for (key, value) in [
        (
            "SIGNING_CONFIG",
            json!("${{ secrets.WINDOWS_SIGNING_CONFIG }}"),
        ),
        ("SIGNING_CONFIG", Value::Null),
        ("BUILD_CONFIG", Value::Null),
        ("STORAGE_CONFIG", Value::Null),
        (
            "INPUT_PUBLIC_CANDIDATES_DIR",
            json!("${{ github.workspace }}/private"),
        ),
        ("RESOLVED_SOURCE_SHA", json!("foreign-source")),
        ("RELEASE_TARGET", json!("package-signatures")),
        ("GH_TOKEN", json!("${{ secrets.GITHUB_TOKEN }}")),
        (
            "PRIVATE_RELEASE_TOKEN",
            json!("${{ secrets.PRIVATE_RELEASE_TOKEN }}"),
        ),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["option1_signatures"]["steps"][1]["env"][key] = value;
        candidate_rejected(&doc);
    }
}

#[test]
fn protected_candidate_download_cannot_cross_runs_or_bypass_the_bound_signer() {
    for (key, value) in [
        ("pattern", json!("*")),
        ("path", json!("private")),
        ("merge-multiple", json!(true)),
        ("run-id", json!("previous-run")),
        ("repository", json!("other/repository")),
        (
            "github-token",
            json!("${{ secrets.PRIVATE_RELEASE_TOKEN }}"),
        ),
        ("name", json!("private-diagnostics")),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["option1_signatures"]["steps"][0]["with"][key] = value;
        candidate_rejected(&doc);
    }
    for (index, key, value) in [
        (
            0,
            "uses",
            json!("actions/download-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ),
        (0, "id", json!("public_candidates_download")),
        (0, "env", json!({"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"})),
        (1, "id", json!("foreign_signer")),
        (1, "run", json!("bash ci/native-release/run.sh run")),
        (1, "if", json!("${{ always() }}")),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["option1_signatures"]["steps"][index][key] = value;
        candidate_rejected(&doc);
    }
    let mut doc = public_candidates_workflow();
    doc["jobs"]["option1_signatures"]["steps"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({"run": "replace candidate bytes"}));
    candidate_rejected(&doc);
    let mut doc = public_candidates_workflow();
    doc["jobs"]["option1_signatures"]["steps"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    candidate_rejected(&doc);
}

#[test]
fn all_public_candidate_roles_require_explicit_option1_route_guards() {
    let mut doc = public_candidates_workflow();
    doc["jobs"]["verify"]["steps"][1]["if"] =
        json!("${{ success() && matrix.target != 'ios' && !inputs.build_only }}");
    candidate_rejected(&doc);
    for job in ["publish", "option1_signatures"] {
        let mut doc = public_candidates_workflow();
        let condition = doc["jobs"][job]["if"]
            .as_str()
            .unwrap()
            .replace(" && inputs.release_route == 'option1'", "");
        doc["jobs"][job]["if"] = json!(condition);
        candidate_rejected(&doc);
        let mut doc = public_candidates_workflow();
        let condition = doc["jobs"][job]["if"]
            .as_str()
            .unwrap()
            .replace("'option1'", "'legacy-acceptance'");
        doc["jobs"][job]["if"] = json!(condition);
        candidate_rejected(&doc);
    }
}

#[test]
fn protected_candidate_download_cannot_be_reused_after_direct_audit() {
    for parent in ["aa-parent", "zz-parent"] {
        let dir = fixture();
        let mut doc = public_candidates_workflow();
        doc["jobs"].as_object_mut().unwrap().remove("verify");
        doc["jobs"].as_object_mut().unwrap().remove("publish");
        put_candidate_workflow(dir.path(), &doc);
        let output = audit(dir.path());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        put(
            dir.path(),
            &format!(".github/workflows/{parent}.yml"),
            "jobs:\n  call:\n    uses: ./.github/workflows/release.yml\n",
        );
        rejected(dir.path(), "actions_storage_forbidden");
    }
}

#[test]
fn public_candidate_producer_oidc_and_signing_dlib_are_scoped_to_the_sdk_role() {
    let mut doc = public_candidates_workflow();
    doc["jobs"]["verify"]["permissions"]["id-token"] = json!("write");
    candidate_rejected(&doc);
    for value in [
        json!("foreign-signing.dll"),
        json!("${{ secrets.WINDOWS_SIGNING_CONFIG }}"),
        json!(
            "${{ !inputs.build_only && matrix.target == 'windows' && format('{0}/artifact-signing/package/bin/x64/Azure.CodeSigning.Dlib.dll', runner.temp) || '' }}"
        ),
    ] {
        let mut doc = public_candidates_workflow();
        doc["jobs"]["verify"]["steps"][0]["env"]["OMNI_WINDOWS_ARTIFACT_SIGNING_DLIB"] = value;
        candidate_rejected(&doc);
    }
}

#[test]
fn standard_labels_only() {
    let dir = fixture();
    assert_eq!(RUNNERS.len(), 6);
    for runner in RUNNERS {
        put(
            dir.path(),
            ".github/workflows/check.yml",
            &format!(
                "name: Check\non: workflow_dispatch\njobs:\n  check:\n    runs-on: {runner}\n    steps:\n      - run: echo checked\n"
            ),
        );
        let result = audit(dir.path());
        assert!(
            result.status.success(),
            "valid runner rejected: {runner}; {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(codes(&result).is_empty());
    }
    for runner in [
        "self-hosted",
        "macos-26-large",
        "ubuntu-latest",
        "windows-2022",
        "gpu-4-core",
        "private-diagnostic-value",
    ] {
        put(
            dir.path(),
            ".github/workflows/check.yml",
            &format!("jobs:\n  check:\n    runs-on: {runner}\n"),
        );
        rejected(dir.path(), "runner_not_allowed");
        assert!(
            !String::from_utf8_lossy(&audit(dir.path()).stdout)
                .contains("private-diagnostic-value")
        );
    }
}
#[test]
fn runner_group_and_expression_are_rejected() {
    let dir = fixture();
    for selection in [
        "[self-hosted, ubuntu-24.04]",
        "{group: free, labels: ubuntu-24.04}",
        "'${{ inputs.runner }}'",
        "'${{ fromJSON(inputs.runner) }}'",
    ] {
        put(
            dir.path(),
            ".github/workflows/check.yml",
            &format!("jobs:\n  check:\n    runs-on: {selection}\n"),
        );
        rejected(dir.path(), "runner_not_static");
    }
}
#[test]
fn matrix_and_reusable_edges_are_closed() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  fanout:\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04, windows-2025]\n        exclude:\n          - runner: windows-2025\n        include:\n          - runner: macos-26\n    runs-on: '${{ matrix.runner }}'\n  child:\n    uses: ./.github/workflows/child.yml\n",
    );
    put(
        dir.path(),
        ".github/workflows/child.yml",
        "on: workflow_call\njobs:\n  check:\n    runs-on: ubuntu-24.04-arm\n",
    );
    assert!(audit(dir.path()).status.success());
    put(
        dir.path(),
        ".github/workflows/child.yml",
        "jobs:\n  check:\n    runs-on: paid-64-core\n",
    );
    rejected(dir.path(), "runner_not_allowed");
    put(
        dir.path(),
        ".github/workflows/child.yml",
        "jobs:\n  loop:\n    uses: ./.github/workflows/check.yml\n",
    );
    rejected(dir.path(), "reusable_cycle");
}
#[test]
fn include_cannot_hide_paid_runner_and_unknown_matrix_fails() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  fanout:\n    runs-on: '${{ matrix.runner }}'\n    strategy:\n      matrix:\n        include:\n          - runner: ubuntu-24.04\n          - runner: macos-26-xlarge\n",
    );
    rejected(dir.path(), "runner_not_allowed");
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  fanout:\n    runs-on: '${{ matrix.runner }}'\n    strategy:\n      matrix: '${{ fromJSON(needs.plan.outputs.matrix) }}'\n",
    );
    rejected(dir.path(), "matrix_not_static");
}
#[test]
fn remote_reusable_workflow_cannot_hide_runner_cost() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    uses: private-owner/source/.github/workflows/check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    rejected(dir.path(), "reusable_not_local");
}
#[test]
fn artifacts_cache_snapshot_and_unknown_actions_are_rejected() {
    let dir = fixture();
    for action in [
        "actions/upload-artifact",
        "actions/download-artifact",
        "actions/cache",
    ] {
        put(
            dir.path(),
            ".github/workflows/check.yml",
            &format!(
                "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: {action}@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            ),
        );
        rejected(dir.path(), "actions_storage_forbidden");
    }
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    snapshot: snapshot-name\n",
    );
    rejected(dir.path(), "snapshot_forbidden");
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: unreviewed/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    rejected(dir.path(), "action_not_reviewed");
}
#[test]
fn implicit_cache_is_rejected() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/setup-node@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n        with:\n          node-version: '24'\n",
    );
    rejected(dir.path(), "implicit_cache_forbidden");
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/setup-node@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n        with:\n          node-version: '24'\n          package-manager-cache: false\n",
    );
    assert!(audit(dir.path()).status.success());
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/setup-go@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    rejected(dir.path(), "implicit_cache_forbidden");
}
#[test]
fn local_composite_actions_are_audited_transitively() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./ci/local\n",
    );
    put(
        dir.path(),
        "ci/local/action.yml",
        "runs:\n  using: composite\n  steps:\n    - uses: actions/upload-artifact@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    rejected(dir.path(), "actions_storage_forbidden");
    put(
        dir.path(),
        "ci/local/action.yml",
        "runs:\n  using: composite\n  steps:\n    - uses: ./ci/local\n",
    );
    rejected(dir.path(), "action_cycle");
}
#[test]
fn duplicate_yaml_and_aliases_fail_closed() {
    let dir = fixture();
    for source in [
        "jobs:\n  check:\n    runs-on: paid\n    runs-on: ubuntu-24.04\n",
        "x: &shared ubuntu-24.04\njobs:\n  check:\n    runs-on: *shared\n",
    ] {
        put(dir.path(), ".github/workflows/check.yml", source);
        rejected(dir.path(), "workflow_invalid");
    }
}
#[test]
fn relative_paths_work_in_the_actual_workflow_command() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n",
    );
    for path in [".github/workflows", ".github/workflows/check.yml"] {
        let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .args([
                "audit-runners",
                "--workflows",
                path,
                "--policy",
                "policy.json",
            ])
            .current_dir(dir.path())
            .env_remove("GITHUB_ACTIONS")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(codes(&output).is_empty());
    }
}
#[test]
fn normal_github_negation_is_not_yaml_indirection() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    if: ${{ !cancelled() }}\n    runs-on: ubuntu-24.04\n",
    );
    assert!(audit(dir.path()).status.success());
}
#[test]
fn unicode_aliases_and_yaml_tags_remain_rejected() {
    let dir = fixture();
    for text in [
        "x: &标签 ubuntu-24.04\njobs:\n  check:\n    runs-on: *标签\n",
        "jobs:\n  check:\n    runs-on: !runner ubuntu-24.04\n",
    ] {
        put(dir.path(), ".github/workflows/check.yml", text);
        rejected(dir.path(), "workflow_invalid");
    }
}
#[test]
fn empty_and_oversized_workflows_do_not_pass() {
    let dir = fixture();
    rejected(dir.path(), "workflow_inventory_empty");
    put(dir.path(), ".github/workflows/check.yml", "jobs: {}\n");
    rejected(dir.path(), "workflow_inventory_empty");
    put(
        dir.path(),
        ".github/workflows/check.yml",
        &"a".repeat(1_048_577),
    );
    rejected(dir.path(), "workflow_invalid");
}
#[test]
fn private_origin_is_rejected() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .args(["audit-runners", "--workflows"])
        .arg(dir.path().join(".github/workflows"))
        .arg("--policy")
        .arg(dir.path().join("policy.json"))
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "ql-owo-lp/omniterm")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(codes(&output).contains(&"execution_origin_invalid".into()));
}
#[test]
fn policy_file_cannot_widen_free_runner_set() {
    let dir = fixture();
    put(
        dir.path(),
        ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: macos-26-large\n",
    );
    let mut policy: Value =
        serde_json::from_slice(&fs::read(dir.path().join("policy.json")).unwrap()).unwrap();
    policy["runners"]
        .as_array_mut()
        .unwrap()
        .push(json!("macos-26-large"));
    put(dir.path(), "policy.json", &policy.to_string());
    rejected(dir.path(), "policy_invalid");
}
#[test]
fn contracts_use_strict_policy_before_downstream_allocation() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let path = repository.join(".github/workflows/contracts.yml");
    let document: Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["jobs"]["policy"]["runs-on"], "ubuntu-24.04");
    for (name, job) in document["jobs"].as_object().unwrap() {
        if name != "policy" {
            assert_eq!(job["needs"], "policy", "policy must gate {name}");
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .args(["audit-runners", "--workflows"])
        .arg(path)
        .arg("--policy")
        .arg(repository.join("ci/standard-runner-policy.json"))
        .env_remove("GITHUB_ACTIONS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(codes(&output).is_empty());
}
#[test]
fn standard_runner_upgrade_preserves_required_check_contexts() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let document: Value = serde_yaml::from_slice(
        &fs::read(repository.join(".github/workflows/contracts.yml")).unwrap(),
    )
    .unwrap();
    let job = &document["jobs"]["contracts"];
    assert_eq!(
        job["name"], "contracts (${{ matrix.check }})",
        "changing runner labels must not strand the existing required checks"
    );
    assert_eq!(job["runs-on"], "${{ matrix.runner }}");
    let includes = job["strategy"]["matrix"]["include"].as_array().unwrap();
    let expected = [
        ("ubuntu-24.04", "ubuntu-24.04"),
        ("windows-2022", "windows-2025"),
        ("macos-26", "macos-26"),
    ];
    assert_eq!(includes.len(), expected.len());
    for (check, runner) in expected {
        assert_eq!(
            includes
                .iter()
                .filter(|row| row["check"] == check && row["runner"] == runner)
                .count(),
            1
        );
    }
    assert_eq!(job["needs"], "policy");
    assert!(job["steps"].as_array().unwrap().iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|text| text.contains("bash ci/test-native-release.sh"))
    }));
}

#[cfg(unix)]
#[test]
fn symbolic_workflows_and_actions_cannot_escape_review() {
    use std::os::unix::fs::symlink;
    let dir = fixture();
    let other = fixture();
    put(
        other.path(),
        "outside.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-24.04\n",
    );
    symlink(
        other.path().join("outside.yml"),
        dir.path().join(".github/workflows/link.yml"),
    )
    .unwrap();
    rejected(dir.path(), "workflow_invalid");
}
