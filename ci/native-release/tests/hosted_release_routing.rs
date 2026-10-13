//! Scheduling contracts do not substitute for physical-device or provider evidence.
use serde_yaml::Value;
use std::{fs, path::Path};

fn workflow() -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    serde_yaml::from_str(&fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap())
        .unwrap()
}

fn platform_runner(platform: &str) -> &'static str {
    match platform {
        "linux" | "android" | "web" => "ubuntu-24.04",
        "macos" | "ios" => "macos-26",
        "windows" => "windows-2025",
        _ => panic!("unexpected platform"),
    }
}

#[test]
fn full_release_jobs_do_not_wait_for_self_hosted_agents() {
    let workflow = workflow();
    for (name, job) in workflow["jobs"].as_mapping().unwrap() {
        let name = name.as_str().unwrap();
        let selection = serde_yaml::to_string(&job["runs-on"]).unwrap();
        assert!(
            !selection.contains("self-hosted"),
            "{name} still requires a self-hosted Actions agent"
        );
        assert!(
            !selection.contains("windows-2022"),
            "{name} is outside the reviewed standard runner policy"
        );
    }
    for name in ["integration", "installation", "external_tests"] {
        let job = &workflow["jobs"][name];
        assert_eq!(job["runs-on"].as_str(), Some("${{ matrix.runner }}"));
        assert_eq!(job["strategy"]["fail-fast"].as_bool(), Some(false));
        assert_eq!(job["strategy"]["max-parallel"].as_u64(), Some(6));
        for row in job["strategy"]["matrix"]["include"].as_sequence().unwrap() {
            assert_eq!(
                row["runner"].as_str(),
                Some(platform_runner(row["platform"].as_str().unwrap()))
            );
        }
    }
    for row in workflow["jobs"]["vpn_container"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
    {
        assert_eq!(row["runner"].as_str(), Some("ubuntu-24.04"));
    }
    assert_eq!(
        workflow["jobs"]["managed_rtc_provider"]["runs-on"].as_str(),
        Some("ubuntu-24.04")
    );
    assert_eq!(
        workflow["jobs"]["external_windows_signing"]["runs-on"].as_str(),
        Some("windows-2025")
    );
}

#[test]
fn desktop_devices_have_automatic_defaults_but_mobile_never_fakes_a_physical_device() {
    let w = workflow();
    let integration = &w["jobs"]["integration"];
    for row in integration["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
    {
        let platform = row["platform"].as_str().unwrap();
        let expected = match platform {
            "linux" => "linux",
            "macos" => "macos",
            "windows" => "windows",
            "web" => "chrome",
            "android" | "ios" => "",
            _ => unreachable!(),
        };
        assert_eq!(row["default_device"].as_str(), Some(expected), "{platform}");
    }
    let task = integration["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|step| step["env"]["RELEASE_TARGET"].as_str() == Some("integration"))
        .unwrap();
    assert_eq!(
        task["env"]["OMNI_INTEGRATION_DEVICE"].as_str(),
        Some("${{ vars[matrix.device_variable] || matrix.default_device }}")
    );
}

#[test]
fn integration_prerequisites_fail_before_private_source_execution() {
    let w = workflow();
    let job = &w["jobs"]["integration"];
    let steps = job["steps"].as_sequence().unwrap();
    let check = steps
        .iter()
        .position(|s| {
            s["run"].as_str()
                == Some("bash ci/native-release/run.sh check-integration-prerequisites")
        })
        .expect("integration must diagnose missing configuration before private compilation");
    let run = steps
        .iter()
        .position(|s| s["run"].as_str() == Some("bash ci/native-release/run.sh run"))
        .unwrap();
    assert!(check < run);
    let env = &steps[check]["env"];
    assert_eq!(
        env.as_mapping().unwrap().len(),
        1,
        "presence checker must not receive credential values"
    );
    let flags = env["RELEASE_PREREQUISITE_PRESENCE"].as_str().unwrap();
    for name in [
        "SOURCE_REPOSITORY",
        "SOURCE_BRANCH",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_KNOWN_HOSTS",
        "BUILD_CONFIG",
        "STORAGE_CONFIG",
        "OMNITERM_VPN_PROVIDER_PUBLIC_KEY",
        "OMNI_INTEGRATION_DEVICE",
    ] {
        assert!(flags.contains(name), "missing configuration check: {name}");
    }
    assert!(flags.contains("secrets.STORAGE_CONFIG != ''"));
    assert!(flags.contains("(vars[matrix.device_variable] || matrix.default_device) != ''"));
    assert!(
        !flags.contains("OMNI_INTEGRATION_DEFINES"),
        "optional fixture override must not become an unconditional prerequisite"
    );
    assert!(job["continue-on-error"].is_null());
}
