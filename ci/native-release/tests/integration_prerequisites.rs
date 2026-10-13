use serde_json::{Value, json};
use std::process::{Command, Output};

const NAMES: [&str; 8] = [
    "SOURCE_REPOSITORY",
    "SOURCE_BRANCH",
    "SOURCE_DEPLOY_KEY",
    "SOURCE_KNOWN_HOSTS",
    "BUILD_CONFIG",
    "STORAGE_CONFIG",
    "OMNITERM_VPN_PROVIDER_PUBLIC_KEY",
    "OMNI_INTEGRATION_DEVICE",
];
fn check(raw: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("check-integration-prerequisites")
        .env_clear()
        .env("RELEASE_PREREQUISITE_PRESENCE", raw)
        .output()
        .unwrap()
}
fn complete() -> Value {
    Value::Object(
        NAMES
            .into_iter()
            .map(|name| (name.to_owned(), json!(true)))
            .collect(),
    )
}
#[test]
fn present_configuration_is_not_reported_as_executed_tests_or_release_evidence() {
    let output = check(&complete().to_string());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "Integration configuration names are present; values, devices and execution evidence remain unverified."
    );
}
#[test]
fn reports_every_missing_name_without_printing_values() {
    let mut value = complete();
    for name in [
        "STORAGE_CONFIG",
        "OMNITERM_VPN_PROVIDER_PUBLIC_KEY",
        "OMNI_INTEGRATION_DEVICE",
    ] {
        value[name] = json!(false);
    }
    let output = check(&value.to_string());
    assert!(!output.status.success());
    let errors = String::from_utf8(output.stderr).unwrap();
    for name in [
        "STORAGE_CONFIG",
        "OMNITERM_VPN_PROVIDER_PUBLIC_KEY",
        "OMNI_INTEGRATION_DEVICE",
    ] {
        assert!(
            errors.contains(&format!("Missing integration prerequisite: {name}")),
            "{errors}"
        );
    }
    assert!(!errors.contains("SOURCE_DEPLOY_KEY"));
}
#[test]
fn malformed_missing_duplicate_unknown_or_nonboolean_input_fails_closed() {
    let complete = complete();
    let mut secret = complete.clone();
    secret["SOURCE_DEPLOY_KEY"] = json!("private-sentinel-do-not-print");
    let mut missing = complete.clone();
    missing.as_object_mut().unwrap().remove("BUILD_CONFIG");
    let mut unknown = complete.clone();
    unknown["private-sentinel-do-not-print"] = json!(true);
    let raw = complete.to_string();
    let duplicate = format!("{{\"BUILD_CONFIG\":true,{}", &raw[1..]);
    for raw in [
        "{}".to_owned(),
        "[]".into(),
        secret.to_string(),
        missing.to_string(),
        unknown.to_string(),
        duplicate,
        "{".into(),
        "x".repeat(9000),
    ] {
        let output = check(&raw);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-sentinel"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-sentinel"));
    }
}
