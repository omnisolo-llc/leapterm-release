//! Owned interface/local path checks. No candidate, signer, provider or release qualification.
use omni_release_launcher::{Environment, input::Request, private_final_archive};
use serde_json::json;
fn request(build_only: bool) -> Request {
    Request::parse(&json!({"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"version":"1.2.3","build_number":"42",
        "ios_action":if build_only {"skip"}else{"submit"},"build_only":build_only,"include_selfhost":true,"automatic_release":false,"release_route":"option1"}).to_string()).unwrap()
}
#[test]
fn approved_recipient_forwarding_covers_all_six_native_builds_after_freeze() {
    let env = Environment::from([
        (
            "DIAGNOSTICS_PUBLIC_KEY".into(),
            "owned local public recipient fixture".into(),
        ),
        ("SOURCE_DEPLOY_KEY".into(), "must not forward".into()),
    ]);
    for target in ["linux", "windows", "macos", "android", "ios", "web"] {
        let mut task = Environment::new();
        private_final_archive::forward(&env, &request(false), target, "verify-build", &mut task)
            .unwrap();
        assert_eq!(task.len(), 1);
        assert_eq!(
            task["DIAGNOSTICS_PUBLIC_KEY"],
            env["DIAGNOSTICS_PUBLIC_KEY"]
        );
    }
}
#[test]
fn build_only_and_unrelated_stages_receive_no_archive_inputs_or_recipient() {
    let env = Environment::from([
        ("DIAGNOSTICS_PUBLIC_KEY".into(), "owned fixture".into()),
        (
            "PRIVATE_FINAL_ARCHIVE_INPUTS_FILE".into(),
            "owned fixture path".into(),
        ),
    ]);
    for (request, target, operation) in [
        (request(true), "windows", "verify-build"),
        (request(false), "validate", "run"),
    ] {
        let mut task = Environment::new();
        private_final_archive::forward(&env, &request, target, operation, &mut task).unwrap();
        assert!(task.is_empty());
    }
}
#[test]
fn archive_prepare_and_legacy_preservation_require_protected_input_but_readback_does_not() {
    let env = Environment::from([("DIAGNOSTICS_PUBLIC_KEY".into(), "owned fixture".into())]);
    let legacy = Request::parse(
        &json!({
            "source_sha": "a".repeat(40),
            "builder_sha": "b".repeat(40),
            "version": "1.2.3",
            "build_number": "42",
            "ios_action": "submit",
            "build_only": false,
            "include_selfhost": true,
            "automatic_release": false,
            "release_route": "legacy-acceptance"
        })
        .to_string(),
    )
    .unwrap();
    for operation in ["prepare-private-final-archive", "run"] {
        assert!(
            private_final_archive::forward(
                &env,
                &legacy,
                "publish",
                operation,
                &mut Environment::new()
            )
            .is_err()
        );
    }
    let mut option1_task = Environment::new();
    private_final_archive::forward(
        &env,
        &request(false),
        "publish",
        "prepare-private-final-archive",
        &mut option1_task,
    )
    .unwrap();
    assert!(!option1_task.contains_key("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE"));
    let mut task = Environment::new();
    private_final_archive::forward(
        &env,
        &request(false),
        "publish",
        "verify-private-final-archive",
        &mut task,
    )
    .unwrap();
    assert!(!task.contains_key("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE"));
}
#[test]
fn native_archive_arguments_use_fixed_plan_paths_and_protected_work_receipt() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let work = root.path().join("owned-work");
    std::fs::create_dir(&work).unwrap();
    let env = Environment::from([
        (
            "RUNNER_TEMP".into(),
            root.path().to_string_lossy().into_owned(),
        ),
        (
            "INPUT_PUBLIC_CANDIDATES_DIR".into(),
            root.path()
                .join("actual-input")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "PRIVATE_FINAL_ARCHIVE_INPUTS_FILE".into(),
            root.path()
                .join("operator.json")
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    let prepared =
        private_final_archive::arguments("prepare-private-final-archive", &env, &work).unwrap();
    assert!(prepared.windows(2).any(|pair| pair[0] == "--receipt"
        && pair[1] == work.join("private-final-archive.json").to_string_lossy()));
    assert!(
        prepared
            .windows(2)
            .any(|pair| pair[0] == "--operator-inputs"
                && pair[1] == env["PRIVATE_FINAL_ARCHIVE_INPUTS_FILE"])
    );
    let verify =
        private_final_archive::arguments("verify-private-final-archive", &env, &work).unwrap();
    assert!(!verify.contains(&"--operator-inputs".into()));
    assert!(private_final_archive::arguments("caller-labelled-complete", &env, &work).is_err());
}
#[test]
fn missing_genuine_plan_and_archive_proof_denies_publication_before_api_effects() {
    assert!(private_final_archive::require_publication(&Environment::new()).is_err());
}
