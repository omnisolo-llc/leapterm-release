use omni_release_launcher::{
    Environment,
    input::{self, Request},
    launch,
};
use serde_json::{Value, json};
use std::{fs, process::Command};
fn env() -> Environment {
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
        ("SOURCE_DEPLOY_KEY".into(), "synthetic".into()),
        ("SOURCE_KNOWN_HOSTS".into(), "synthetic".into()),
        (
            "OMNITERM_VPN_PROVIDER_PUBLIC_KEY".into(),
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [1u8; 32]),
        ),
        ("RELEASE_TARGET".into(), "linux".into()),
        (
            "RELEASE_REQUEST".into(),
            json!({"build_only":true,"source_sha":"a".repeat(40),"build_number":"42"}).to_string(),
        ),
    ])
}
// Public fixture bytes only: no operator credentials or deployed trust keys.
#[test]
fn application_builds_reject_missing_or_malformed_trust_keys_before_acquisition() {
    const KEY: &str = "OMNITERM_VPN_PROVIDER_PUBLIC_KEY";
    for target in input::BUILD_TARGETS {
        let mut environment = env();
        environment.insert("RELEASE_TARGET".into(), target.to_string());
        environment.remove(KEY);
        assert_eq!(
            launch::validate_configuration(&environment, "run").err(),
            Some(
                "Missing OMNITERM_VPN_PROVIDER_PUBLIC_KEY; configure the reviewed application trust key"
            )
        );
        for invalid in [
            String::new(),
            "not-a-public-key-do-not-echo".into(),
            "A".repeat(43),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF".into(),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\n".into(),
        ] {
            environment.insert(KEY.into(), invalid);
            let error = launch::validate_configuration(&environment, "run").err();
            assert!(error.is_some(), "{target}: invalid trust key accepted");
            assert!(!error.unwrap().contains("do-not-echo"));
        }
        environment.insert(KEY.into(), env()[KEY].clone());
        assert!(launch::validate_configuration(&environment, "run").is_ok());
    }
}

#[test]
fn resolver_does_not_need_application_trust_material() {
    let mut environment = env();
    environment.remove("OMNITERM_VPN_PROVIDER_PUBLIC_KEY");
    environment.insert("RELEASE_TARGET".into(), "resolve".into());
    assert!(launch::validate_configuration(&environment, "resolve").is_ok());
}

#[test]
fn missing_trust_key_is_named_without_creating_checkout_or_build_state() {
    let temp = tempfile::tempdir().unwrap();
    let mut environment = env();
    environment.remove("OMNITERM_VPN_PROVIDER_PUBLIC_KEY");
    environment.insert(
        "RUNNER_TEMP".into(),
        temp.path().to_string_lossy().into_owned(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("run")
        .env_clear()
        .envs(environment)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Missing OMNITERM_VPN_PROVIDER_PUBLIC_KEY")
    );
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

fn full() -> Value {
    json!({"build_only":false,"source_sha":"a".repeat(40),"builder_sha":"b".repeat(40),"ios_action":"submit","build_number":"42"})
}
#[test]
fn all_targets_validate_configuration_without_unrelated_signing_or_optional_identifiers() {
    let mut build = env();
    for target in input::BUILD_TARGETS {
        build.insert("RELEASE_TARGET".into(), target.to_string());
        launch::validate_configuration(&build, "run").unwrap();
    }
    let mut release = env();
    release.insert("RELEASE_REQUEST".into(), full().to_string());
    release.insert("RESOLVED_SOURCE_SHA".into(), "a".repeat(40));
    release.insert(
        "BUILD_CONFIG".into(),
        r#"{"OMNI_ENABLE_VPN":"true"}"#.into(),
    );
    release.insert("STORAGE_CONFIG".into(), "{}".into());
    for stage in input::RELEASE_TARGETS.iter().filter(|s| **s != "resolve") {
        release.insert("RELEASE_TARGET".into(), stage.to_string());
        launch::validate_configuration(&release, "run").unwrap();
        for key in [
            "SOURCE_DEPLOY_KEY",
            "SOURCE_KNOWN_HOSTS",
            "STORAGE_CONFIG",
            "BUILD_CONFIG",
            "RESOLVED_SOURCE_SHA",
        ] {
            let mut missing = release.clone();
            missing.remove(key);
            assert!(
                launch::validate_configuration(&missing, "run").is_err(),
                "{stage}:{key}"
            );
        }
        for config in [
            "",
            "{}",
            r#"{"OMNI_ENABLE_VPN":false}"#,
            r#"{"OMNI_ENABLE_VPN":true}"#,
            r#"{"OMNI_ENABLE_VPN":"false"}"#,
            r#"{"OMNI_ENABLE_VPN":"true","OMNI_ENABLE_VPN":"true"}"#,
        ] {
            let mut bad = release.clone();
            bad.insert("BUILD_CONFIG".into(), config.into());
            assert!(launch::validate_configuration(&bad, "run").is_err());
        }
    }
    let mut resolve = release.clone();
    resolve.insert("RELEASE_TARGET".into(), "resolve".into());
    resolve.remove("BUILD_CONFIG");
    resolve.remove("STORAGE_CONFIG");
    resolve.insert("APPROVED_RELEASE_SOURCE_SHA".into(), "a".repeat(40));
    resolve.insert("APPROVED_RELEASE_BUILDER_SHA".into(), "b".repeat(40));
    launch::validate_configuration(&resolve, "resolve").unwrap();
}
#[test]
fn full_release_resolves_latest_main_without_manual_sha_approvals() {
    let mut environment = env();
    let mut request = full();
    request["source_sha"] = json!("");
    request["builder_sha"] = json!("");
    environment.insert("RELEASE_TARGET".into(), "resolve".into());
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    let resolved = launch::validate_configuration(&environment, "resolve")
        .expect("an authorized request may select main automatically");
    assert!(resolved.source_sha.is_empty());
    assert_eq!(resolved.builder_sha, "b".repeat(40));
}

#[test]
fn full_release_keeps_explicit_sha_and_binds_later_jobs_to_resolver() {
    let mut environment = env();
    let mut request = full();
    environment.insert("RELEASE_TARGET".into(), "resolve".into());
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    assert_eq!(
        launch::validate_configuration(&environment, "resolve")
            .unwrap()
            .source_sha,
        "a".repeat(40)
    );
    request["source_sha"] = json!("");
    request["builder_sha"] = json!("");
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    environment.insert("RELEASE_TARGET".into(), "linux".into());
    environment.insert("RESOLVED_SOURCE_SHA".into(), "c".repeat(40));
    environment.insert(
        "BUILD_CONFIG".into(),
        r#"{"OMNI_ENABLE_VPN":"true"}"#.into(),
    );
    environment.insert("STORAGE_CONFIG".into(), "{}".into());
    assert_eq!(
        launch::validate_configuration(&environment, "run")
            .unwrap()
            .source_sha,
        "c".repeat(40)
    );
    request["source_sha"] = json!("a".repeat(40));
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    assert!(launch::validate_configuration(&environment, "run").is_err());
    request["source_sha"] = json!("");
    request["builder_sha"] = json!("d".repeat(40));
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    assert!(launch::validate_configuration(&environment, "run").is_err());
    request["builder_sha"] = json!("");
    environment.insert("RELEASE_REQUEST".into(), request.to_string());
    environment.remove("RESOLVED_SOURCE_SHA");
    assert!(launch::validate_configuration(&environment, "run").is_err());
}

#[test]
fn foreign_identity_paths_commands_and_missing_fields_fail_before_any_acquisition() {
    for (key, values) in [
        (
            "SOURCE_REPOSITORY",
            vec!["https://example/repo", "a/b/c", "a/b\n", "foreign/private"],
        ),
        (
            "SOURCE_BRANCH",
            vec!["-main", "main\n", "../x", "x/.bad", "x.lock", "other"],
        ),
        ("SOURCE_ENTRYPOINT", vec!["legacy"]),
        (
            "RELEASE_TARGET",
            vec!["docker", "linux; echo unsafe", "-linux"],
        ),
        ("GITHUB_EVENT_NAME", vec!["pull_request", "push"]),
        ("GITHUB_RUN_ID", vec!["0", "01", "x", "1\n"]),
    ] {
        for value in values {
            let mut bad = env();
            bad.insert(key.into(), value.into());
            assert!(
                launch::validate_configuration(&bad, "run").is_err(),
                "{key}:{value}"
            );
        }
    }
    for key in env().keys() {
        let mut bad = env();
        bad.remove(key);
        assert!(
            launch::validate_configuration(&bad, "run").is_err(),
            "{key}"
        );
    }
    for stage in input::RELEASE_TARGETS {
        let mut bad = env();
        bad.insert("RELEASE_TARGET".into(), stage.to_string());
        bad.insert(
            "GITHUB_WORKFLOW_REF".into(),
            "attacker/private-workflow".into(),
        );
        bad.insert(
            "SOURCE_DEPLOY_KEY".into(),
            "confidential-secret-sentinel".into(),
        );
        let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .arg(if *stage == "resolve" {
                "resolve"
            } else {
                "run"
            })
            .env_clear()
            .envs(bad)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(logs.contains("authority"));
        assert!(!logs.contains("confidential") && !logs.contains("attacker"));
    }
}
#[test]
fn numeric_versions_source_defaults_resolution_preview_and_boolean_contracts_are_exact() {
    for version in [json!("0.0.0"), json!("9999.9999.9999")] {
        Request::parse(
            &json!({"build_only":true,"build_number":"1","version":version}).to_string(),
        )
        .unwrap();
    }
    for version in [
        json!("10000.0.0"),
        json!("01.0.0"),
        json!("1.2"),
        json!("1.2.3.4"),
        json!(null),
        json!(3),
    ] {
        assert!(
            Request::parse(
                &json!({"build_only":true,"build_number":"1","version":version}).to_string()
            )
            .is_err()
        );
    }
    let input =
        Request::parse(r#"{"build_only":true,"build_number":"1","include_selfhost":false}"#)
            .unwrap();
    let normalized: Value = serde_json::from_str(&input.normalized().unwrap()).unwrap();
    assert_eq!(
        normalized
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "release_route",
            "build_only",
            "source_sha",
            "version",
            "build_number",
            "ios_action",
            "automatic_release",
            "include_selfhost",
        ])
    );
    assert_eq!(normalized["release_route"], "option1");
    assert_eq!(normalized["include_selfhost"], false);
    for number in ["1", "42", "9999"] {
        Request::parse(&json!({"build_only":true,"build_number":number}).to_string()).unwrap();
    }
    for number in [
        json!(0),
        json!(1),
        json!(true),
        json!(null),
        json!(""),
        json!("0"),
        json!("0001"),
        json!("10000"),
        json!("1\n"),
    ] {
        assert!(
            Request::parse(&json!({"build_only":true,"build_number":number}).to_string()).is_err()
        );
    }
    let mut parsed =
        Request::parse(r#"{"build_only":true,"build_number":"42","version":""}"#).unwrap();
    assert!(parsed.source_sha.is_empty());
    assert_eq!(parsed.version, "0.1.0");
    parsed
        .resolve_from(&Environment::from([(
            "RESOLVED_SOURCE_SHA".into(),
            "a".repeat(40),
        )]))
        .unwrap();
    assert_eq!(parsed.source_sha, "a".repeat(40));
    for field in [
        "build_only",
        "automatic_release",
        "include_selfhost",
        "preview_windows_self_sign",
    ] {
        for value in [json!("true"), json!("false"), json!(null), json!(1)] {
            let mut raw = json!({"build_only":true,"build_number":"1"});
            raw[field] = value;
            assert!(Request::parse(&raw.to_string()).is_err(), "{field}");
        }
    }
    for selected in input::BUILD_TARGETS {
        let mut raw = full();
        raw["verify_target"] = json!(selected);
        assert!(Request::parse(&raw.to_string()).is_err());
    }
    for action in ["upload", "submit"] {
        let mut raw = full();
        raw["ios_action"] = json!(action);
        Request::parse(&raw.to_string()).unwrap();
    }
    for changes in [json!({"source_sha":""}), json!({"builder_sha":""})] {
        let mut raw = full();
        for (key, value) in changes.as_object().unwrap() {
            raw[key] = value.clone();
        }
        let mut e = env();
        e.insert("RELEASE_REQUEST".into(), raw.to_string());
        e.insert("RELEASE_TARGET".into(), "resolve".into());
        let resolved = launch::validate_configuration(&e, "resolve").unwrap();
        assert_eq!(resolved.source_sha, raw["source_sha"].as_str().unwrap());
        assert_eq!(resolved.builder_sha, "b".repeat(40));
    }
}
#[test]
fn workflow_output_names_accept_sdk_and_publication_sha256_identifiers() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    fs::write(&output, "previous=retained\n").unwrap();
    let e = Environment::from([("GITHUB_OUTPUT".into(), output.to_str().unwrap().into())]);
    launch::write_outputs(
        &e,
        &[
            ("manifest_sha256", "sdk-digest"),
            ("native_verifier_sha256", "verifier-digest"),
            ("publication_plan_sha256", "plan-digest"),
            ("_receipt_2", "receipt"),
            ("_", "empty-value-follows"),
            ("a0", ""),
        ],
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "previous=retained\nmanifest_sha256=sdk-digest\nnative_verifier_sha256=verifier-digest\npublication_plan_sha256=plan-digest\n_receipt_2=receipt\n_=empty-value-follows\na0=\n"
    );
}

#[test]
fn workflow_output_names_reject_empty_leading_digits_and_injection_without_appending() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    fs::write(&output, "previous=retained\n").unwrap();
    let e = Environment::from([("GITHUB_OUTPUT".into(), output.to_str().unwrap().into())]);
    for key in [
        "",
        "0leading",
        "Manifest",
        "manifest-sha256",
        "manifest.sha256",
        "manifest=sha256",
        "manifest/sha256",
        "manifest sha256",
        "manifest\ninjected",
        "manifest\rinjected",
        "manifest\0injected",
        "manifést",
    ] {
        assert_eq!(
            launch::write_outputs(&e, &[("source_sha", "safe"), (key, "digest")]).err(),
            Some("Unsafe workflow output value"),
            "{key:?}"
        );
        assert_eq!(fs::read(&output).unwrap(), b"previous=retained\n");
    }
}

#[test]
fn workflow_output_values_reject_injection_without_appending_earlier_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    fs::write(&output, "previous=retained\n").unwrap();
    let e = Environment::from([("GITHUB_OUTPUT".into(), output.to_str().unwrap().into())]);
    for value in ["safe\nEVIL=x", "safe\rEVIL=x", "safe\0EVIL=x"] {
        assert_eq!(
            launch::write_outputs(&e, &[("source_sha", "safe"), ("builder_sha", value)]).err(),
            Some("Unsafe workflow output value")
        );
        assert_eq!(fs::read(&output).unwrap(), b"previous=retained\n");
    }
}

#[test]
fn workflow_output_file_rejects_links_directories_and_newline_injection() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    fs::write(&output, "").unwrap();
    let e = Environment::from([("GITHUB_OUTPUT".into(), output.to_str().unwrap().into())]);
    assert!(launch::write_outputs(&e, &[("source_sha", "safe\nEVIL=x")]).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"");
    fs::hard_link(&output, temp.path().join("alias")).unwrap();
    assert!(launch::write_outputs(&e, &[("source_sha", "safe")]).is_err());
    let dir = Environment::from([("GITHUB_OUTPUT".into(), temp.path().to_str().unwrap().into())]);
    assert!(launch::write_outputs(&dir, &[("source_sha", "safe")]).is_err());
    #[cfg(unix)]
    {
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        let e = Environment::from([("GITHUB_OUTPUT".into(), link.to_str().unwrap().into())]);
        assert!(launch::write_outputs(&e, &[("source_sha", "safe")]).is_err());
    }
}
#[test]
fn ssh_selection_and_key_decoding_are_bounded_scoped_and_do_not_accept_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let expected = temp.path().join("Git/usr/bin/ssh.exe");
    for layout in ["cmd/git.exe", "bin/git.exe", "mingw64/bin/git.exe"] {
        assert!(
            launch::git_ssh_candidates(&temp.path().join("Git").join(layout)).contains(&expected)
        );
    }
    let clean = omni_release_launcher::clean_environment(&std::env::vars().collect());
    let ssh = launch::ssh_executable(&clean).unwrap();
    let version = Command::new(ssh).arg("-V").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stderr).contains("OpenSSH"));
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"-----BEGIN SYNTHETIC PRIVATE KEY-----\r\nfixture\r\n-----END SYNTHETIC PRIVATE KEY-----",
    );
    assert!(
        launch::decode_submodule_key(&encoded)
            .unwrap()
            .ends_with(b"\n")
    );
    for value in ["not a key", "bm90IGEga2V5", &"a".repeat(65537)] {
        assert!(launch::decode_submodule_key(value).is_err());
    }
    let e = launch::checkout_environment(
        &clean,
        &temp.path().join("key with '$ characters"),
        &temp.path().join("hosts"),
    )
    .unwrap();
    assert!(e["GIT_SSH_COMMAND"].contains("IdentityAgent=none"));
    assert!(!e.contains_key("SOURCE_SUBMODULE_DEPLOY_KEY_BASE64"));
}
#[test]
fn diagnostic_phase_and_error_classification_never_echo_private_input() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("status");
    for raw in [
        r#"{"stage":"confidential/path"}"#,
        r#"{"stage":"application-build","error":"private output"}"#,
    ] {
        fs::write(&path, raw).unwrap();
        let phase = launch::diagnostic_phase(&path);
        assert!(!phase.contains("confidential") && !phase.contains("private output"));
    }
    fs::write(
        &path,
        "secret/path: Host key verification failed; private-token",
    )
    .unwrap();
    assert_eq!(launch::checkout_failure(&path), "host-key-verification");
    fs::write(&path, "private exception details").unwrap();
    assert_eq!(launch::checkout_failure(&path), "unclassified");
}
