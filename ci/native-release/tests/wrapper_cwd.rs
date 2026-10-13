#![cfg(unix)]
//! Exercise the shipped shell wrapper and real locked Rust build. Testing only
//! the compiled CLI missed the working-directory regression on hosted runners.
use serde_json::json;
use std::{fs, path::Path, process::Command};

#[test]
fn actual_shell_wrapper_keeps_relative_arguments_bound_to_the_callers_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("caller with spaces");
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::create_dir(root.join("ci")).unwrap();
    fs::write(
        root.join(".github/workflows/check.yml"),
        "name: Check\non: workflow_dispatch\njobs:\n  check:\n    runs-on: ubuntu-24.04\n",
    )
    .unwrap();
    fs::write(
        root.join("ci/policy.json"),
        json!({
            "schema": 1,
            "repository": "omnisolo-llc/omniterm-release",
            "runners": omni_release_launcher::runner_policy::RUNNERS,
            "prohibit_actions_storage": true
        })
        .to_string(),
    )
    .unwrap();
    let environment = omni_release_launcher::clean_environment(&std::env::vars().collect());
    let output = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("run.sh"))
        .args([
            "audit-runners",
            "--workflows",
            ".github/workflows/check.yml",
            "--policy",
            "ci/policy.json",
        ])
        .env_clear()
        .envs(environment)
        .env("RUNNER_TEMP", temporary.path())
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "actual wrapper rejected valid caller-relative inputs: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"], json!([]));
    assert_eq!(
        fs::read_dir(temporary.path()).unwrap().count(),
        1,
        "launcher build scratch must be cleaned without deleting the caller"
    );
}
