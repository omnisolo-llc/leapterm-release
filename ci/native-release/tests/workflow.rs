use serde_yaml::Value;
use std::{collections::BTreeSet, fs, path::Path};
fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}
fn read(path: &str) -> String {
    fs::read_to_string(repository().join(path)).unwrap()
}
fn workflow(name: &str) -> Value {
    serde_yaml::from_str(&read(&format!(".github/workflows/{name}.yml"))).unwrap()
}
fn steps(job: &Value) -> &[Value] {
    job["steps"].as_sequence().unwrap()
}
fn task(job: &Value) -> &Value {
    steps(job)
        .iter()
        .find(|s| s["env"]["RELEASE_TARGET"].as_str().is_some())
        .unwrap()
}
fn needs(job: &Value) -> BTreeSet<&str> {
    match &job["needs"] {
        Value::String(s) => BTreeSet::from([s.as_str()]),
        Value::Sequence(s) => s.iter().map(|v| v.as_str().unwrap()).collect(),
        _ => BTreeSet::new(),
    }
}
fn require_text(value: &Value, text: &str) {
    assert!(
        serde_yaml::to_string(value).unwrap().contains(text),
        "Missing {text}"
    );
}
#[test]
fn option1_publication_keeps_the_test_matrix_decoupled_and_requires_native_public_candidates() {
    let workflow = workflow("release");
    let verify = &workflow["jobs"]["verify"];
    let publish = &workflow["jobs"]["publish"];
    let signing = &workflow["jobs"]["option1_signatures"];
    assert_eq!(
        needs(publish),
        BTreeSet::from(["resolve", "verify", "option1_signatures"])
    );
    assert_eq!(verify["continue-on-error"].as_bool(), Some(true));
    require_text(publish, "!inputs.build_only");
    let producer = steps(verify)
        .iter()
        .find(|step| step["id"].as_str() == Some("public_candidates"))
        .unwrap();
    assert_eq!(
        producer["run"].as_str(),
        Some("bash ci/native-release/run.sh verify-build")
    );
    for key in ["GH_TOKEN", "GITHUB_TOKEN", "PRIVATE_RELEASE_TOKEN"] {
        assert!(producer["env"][key].is_null());
    }
    assert!(
        steps(verify)
            .iter()
            .all(|step| step["id"].as_str() != Some("public_candidates_upload"))
    );
    let download = steps(publish)
        .iter()
        .find(|step| step["id"].as_str() == Some("public_candidates_download"))
        .unwrap();
    assert_eq!(
        download["run"].as_str(),
        Some("mkdir -p release-public-candidates")
    );
    let preflight = steps(publish)
        .iter()
        .position(|step| step["id"].as_str() == Some("publication_candidates"))
        .unwrap();
    let signer = steps(signing)
        .iter()
        .position(|step| step["id"].as_str() == Some("public_candidate_signatures"))
        .unwrap();
    assert_eq!(needs(signing), BTreeSet::from(["resolve", "verify"]));
    assert_eq!(signing["environment"].as_str(), Some("package-signing"));
    assert_eq!(signing["permissions"]["contents"].as_str(), Some("read"));
    assert_eq!(signing["permissions"].as_mapping().unwrap().len(), 1);
    assert!(signing["continue-on-error"].is_null());
    let signing_node = steps(signing)
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("actions/setup-node@"))
        })
        .unwrap();
    assert_eq!(
        signing_node["with"]["package-manager-cache"].as_bool(),
        Some(false)
    );
    assert_eq!(
        steps(signing)[signer - 1]["id"].as_str(),
        Some("protected_candidates_download")
    );
    assert_eq!(
        steps(signing)[signer - 1]["run"].as_str(),
        Some("mkdir -p release-public-candidates")
    );
    assert_eq!(
        steps(signing)[signer]["run"].as_str(),
        Some("bash ci/native-release/run.sh sign-public-candidates")
    );
    assert_eq!(
        steps(signing)[signer]["env"]["SIGNING_CONFIG"].as_str(),
        Some("${{ secrets.PACKAGE_SIGNING_CONFIG }}")
    );
    for step in steps(signing) {
        for key in ["GH_TOKEN", "GITHUB_TOKEN", "PRIVATE_RELEASE_TOKEN"] {
            assert!(step["env"][key].is_null());
        }
    }
    assert!(steps(publish)[preflight]["env"]["SIGNING_CONFIG"].is_null());
    assert_eq!(
        steps(publish)[preflight]["run"].as_str(),
        Some("bash ci/native-release/run.sh prepare-publication")
    );
    assert_eq!(
        steps(publish)[preflight]["env"]["INPUT_PUBLIC_CANDIDATES_DIR"].as_str(),
        Some("${{ github.workspace }}/release-public-candidates")
    );
    for step in &steps(publish)[..=preflight] {
        for key in ["GH_TOKEN", "GITHUB_TOKEN", "PRIVATE_RELEASE_TOKEN"] {
            assert!(step["env"][key].is_null());
        }
    }
    let writer = steps(publish)
        .iter()
        .find(|s| s["run"].as_str() == Some("bash ci/native-release/run.sh publish-candidates"))
        .unwrap();
    assert_eq!(
        writer["env"]["GH_TOKEN"].as_str(),
        Some("${{ secrets.PRIVATE_RELEASE_TOKEN }}")
    );
    assert_eq!(
        writer["env"]["APPROVED_NATIVE_VERIFIER_SHA256"].as_str(),
        Some("${{ steps.publication_candidates.outputs.native_verifier_sha256 }}")
    );
    assert_eq!(
        writer["env"]["APPROVED_PUBLICATION_PLAN_SHA256"].as_str(),
        Some("${{ steps.publication_candidates.outputs.publication_plan_sha256 }}")
    );
    for key in [
        "GITHUB_TOKEN",
        "PRIVATE_RELEASE_TOKEN",
        "SOURCE_DEPLOY_KEY",
        "SOURCE_SUBMODULE_TOKEN",
        "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
        "STORAGE_CONFIG",
        "SIGNING_CONFIG",
    ] {
        assert!(writer["env"][key].is_null());
    }
    let text = serde_yaml::to_string(publish).unwrap();
    for forbidden in [
        "--clobber",
        "release-dist",
        "release create",
        "release upload",
        "needs.integration",
        "needs.installation",
        "needs.managed_rtc_provider",
    ] {
        assert!(!text.contains(forbidden));
    }
}
#[test]
fn route_selection_assigns_one_version_draft_owner_and_retains_legacy_acceptance() {
    let w = workflow("release");
    let input = &w["on"]["workflow_dispatch"]["inputs"]["release_route"];
    assert_eq!(input["default"].as_str(), Some("option1"));
    assert_eq!(
        input["options"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["option1", "legacy-acceptance"]
    );
    for (name, job) in w["jobs"].as_mapping().unwrap() {
        let name = name.as_str().unwrap();
        let condition = job["if"].as_str().unwrap();
        if name == "publish" {
            assert!(condition.contains("inputs.release_route == 'option1'"));
            assert_eq!(
                needs(job),
                BTreeSet::from(["resolve", "verify", "option1_signatures"])
            );
        } else if name == "option1_signatures" {
            assert!(condition.contains("inputs.release_route == 'option1'"));
            assert_eq!(needs(job), BTreeSet::from(["resolve", "verify"]));
        } else if ![
            "release_source_approval",
            "resolve",
            "windows_sdk",
            "verify",
        ]
        .contains(&name)
        {
            assert!(
                condition.contains("inputs.release_route == 'legacy-acceptance'"),
                "{name}"
            );
            assert!(condition.contains("!inputs.build_only"));
        }
    }
    require_text(
        &w["jobs"]["resolve"],
        "needs.release_source_approval.result == 'success'",
    );
}
#[test]
fn every_public_workflow_uses_native_launch_and_contracts_without_legacy_runtime() {
    for name in ["release", "omni-agent", "contracts"] {
        let parsed = workflow(name);
        assert!(
            !serde_yaml::to_string(&parsed)
                .unwrap()
                .contains("SOURCE_ENTRYPOINT"),
            "{name}: obsolete source entrypoint input"
        );
        for (_, job) in parsed["jobs"].as_mapping().unwrap() {
            for step in steps(job) {
                if let Some(action) = step["uses"].as_str() {
                    assert!(!action.contains("setup-python"));
                }
                if let Some(run) = step["run"].as_str() {
                    for forbidden in ["python", "pip ", "bootstrap.py", ".py'", ".py\""] {
                        assert!(!run.contains(forbidden), "{name}: {run}");
                    }
                }
            }
        }
    }
    let release = workflow("release");
    for (name, job) in release["jobs"].as_mapping().unwrap() {
        let name = name.as_str().unwrap();
        if name == "publish" {
            continue;
        }
        let command = if name == "release_source_approval" {
            "validate-request"
        } else if name == "resolve" {
            "resolve"
        } else if name == "windows_sdk" {
            "windows-sdk"
        } else if name == "verify" {
            "verify-build"
        } else if name == "option1_signatures" {
            "sign-public-candidates"
        } else {
            "run"
        };
        assert!(
            steps(job)
                .iter()
                .any(|s| s["run"].as_str()
                    == Some(&format!("bash ci/native-release/run.sh {command}"))),
            "{name}"
        );
    }
    for name in ["verify", "validate"] {
        require_text(&release["jobs"][name], "bash ci/test-native-release.sh");
    }
    require_text(
        &workflow("contracts")["jobs"]["contracts"],
        "bash ci/test-native-release.sh",
    );
    for entry in fs::read_dir(repository().join("ci")).unwrap() {
        let path = entry.unwrap().path();
        assert_ne!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("py"),
            "legacy Python entrypoint or test remains: {}",
            path.display()
        );
    }
}
#[test]
fn native_shell_entrypoint_has_no_runtime_fallback_and_sanitizes_compilation() {
    let source = read("ci/native-release/run.sh");
    assert_eq!(source.matches("env -i PATH=").count(), 3);
    assert!(source.contains("cargo +1.95.0 build --locked --release"));
    assert!(source.contains("rustup toolchain install 1.95.0 --profile minimal --no-self-update"));
    assert!(source.contains("CARGO_BUILD_JOBS=\"$jobs\""));
    assert!(source.contains("bootstrap.log"));
}
#[test]
fn private_native_contracts_run_before_using_release_tool() {
    let source = read("ci/native-release/src/launch.rs");
    assert!(source.contains("\"test\".into()"));
    assert!(source.contains("tools/release-cli/Cargo.toml"));
}
#[test]
fn complete_same_run_release_graph_keeps_all_evidence_and_approval_edges() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    let edges = [
        ("release_source_approval", vec![]),
        ("resolve", vec!["release_source_approval"]),
        ("windows_sdk", vec!["resolve"]),
        ("integration", vec!["resolve", "windows_sdk"]),
        ("verify", vec!["resolve", "windows_sdk"]),
        ("validate", vec!["resolve", "integration"]),
        ("downloads", vec!["resolve", "validate"]),
        (
            "windows_download",
            vec!["resolve", "validate", "windows_sdk"],
        ),
        ("ios", vec!["resolve", "validate"]),
        (
            "package_signatures",
            vec!["resolve", "validate", "downloads", "windows_download"],
        ),
        ("apple_testflight", vec!["resolve", "validate", "ios"]),
        (
            "installation",
            vec![
                "resolve",
                "validate",
                "downloads",
                "windows_download",
                "ios",
                "package_signatures",
                "apple_testflight",
            ],
        ),
        (
            "vpn_container",
            vec![
                "resolve",
                "validate",
                "downloads",
                "windows_download",
                "ios",
                "package_signatures",
                "apple_testflight",
                "installation",
            ],
        ),
        (
            "ios_delivery",
            vec![
                "resolve",
                "validate",
                "ios",
                "apple_testflight",
                "installation",
                "vpn_container",
            ],
        ),
        (
            "publication_prepare",
            vec![
                "resolve",
                "validate",
                "downloads",
                "windows_download",
                "ios",
                "package_signatures",
                "apple_testflight",
                "installation",
                "vpn_container",
                "ios_delivery",
            ],
        ),
        (
            "managed_rtc_provider",
            vec!["resolve", "publication_prepare"],
        ),
        (
            "external_tests",
            vec!["resolve", "publication_prepare", "managed_rtc_provider"],
        ),
        (
            "external_windows_signing",
            vec!["resolve", "publication_prepare", "external_tests"],
        ),
        (
            "apple_submission",
            vec![
                "resolve",
                "validate",
                "ios_delivery",
                "publication_prepare",
                "vpn_container",
                "external_tests",
                "external_windows_signing",
            ],
        ),
        ("publish", vec!["resolve", "verify", "option1_signatures"]),
        ("option1_signatures", vec!["resolve", "verify"]),
    ];
    assert_eq!(jobs.as_mapping().unwrap().len(), edges.len());
    for (name, parents) in edges {
        let job = &jobs[name];
        assert_eq!(needs(job), parents.into_iter().collect(), "{name}");
        let condition = job["if"].as_str().unwrap();
        assert!(
            condition.contains("github.repository == 'omnisolo-llc/leapterm-release'")
                && condition.contains("github.ref == 'refs/heads/main'"),
            "{name}"
        );
        if !["verify", "resolve", "publish"].contains(&name) {
            assert!(condition.contains("!inputs.build_only"), "{name}");
        }
    }
    let publish = jobs["publish"]["if"].as_str().unwrap();
    assert!(publish.contains("needs.resolve.result == 'success'"));
    assert!(publish.contains("!cancelled()"));
    let apple = jobs["apple_submission"]["if"].as_str().unwrap();
    for parent in [
        "ios_delivery",
        "vpn_container",
        "external_tests",
        "external_windows_signing",
    ] {
        assert!(
            apple.contains(&format!("needs.{parent}.result == 'success'")),
            "{parent}"
        );
    }
    assert!(apple.contains("inputs.ios_action == 'submit'"));
    assert_eq!(
        task(&jobs["apple_submission"])["env"]["RELEASE_IOS_DELIVERY_RESULT"].as_str(),
        Some("${{ needs.ios_delivery.result }}")
    );
    let verify = jobs["verify"]["if"].as_str().unwrap();
    for clause in ["!cancelled()", "needs.resolve.result == 'success'"] {
        assert!(verify.contains(clause));
    }
    assert!(!verify.contains("always()"));
    let resolve = jobs["resolve"]["if"].as_str().unwrap();
    for clause in [
        "!cancelled()",
        "inputs.build_only",
        "needs.release_source_approval.result == 'success'",
    ] {
        assert!(resolve.contains(clause));
    }
}
#[test]
fn permissions_environments_and_all_task_inputs_keep_exact_step_scope() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    let contracts = [
        (
            "release_source_approval",
            "read",
            false,
            "release-source-approval",
            "",
        ),
        ("resolve", "read", false, "downloads", "resolve"),
        ("windows_sdk", "read", false, "downloads", "windows"),
        ("integration", "read", false, "downloads", "integration"),
        ("verify", "read", true, "downloads", "${{ matrix.target }}"),
        ("validate", "write", false, "downloads", "validate"),
        (
            "downloads",
            "write",
            false,
            "downloads",
            "${{ matrix.target }}",
        ),
        ("windows_download", "write", true, "downloads", "windows"),
        ("ios", "write", false, "app-store", "ios"),
        (
            "package_signatures",
            "read",
            false,
            "package-signing",
            "package-signatures",
        ),
        (
            "apple_testflight",
            "write",
            false,
            "app-store",
            "apple-testflight",
        ),
        (
            "installation",
            "read",
            true,
            "${{ matrix.attestation_environment }}",
            "installation",
        ),
        (
            "vpn_container",
            "read",
            true,
            "vpn-container",
            "vpn-container",
        ),
        (
            "managed_rtc_provider",
            "read",
            true,
            "managed-rtc-provider",
            "managed-rtc-provider",
        ),
        ("ios_delivery", "write", false, "app-store", "ios-deliver"),
        (
            "publication_prepare",
            "read",
            false,
            "public-release",
            "publication-prepare",
        ),
        (
            "external_tests",
            "read",
            true,
            "external-tests",
            "external-tests",
        ),
        (
            "external_windows_signing",
            "read",
            true,
            "external-windows-signing",
            "external-windows-signing",
        ),
        ("apple_submission", "read", false, "app-store", "ios-submit"),
        ("publish", "write", false, "public-release", ""),
        (
            "option1_signatures",
            "read",
            false,
            "package-signing",
            "publish",
        ),
    ];
    assert!(w["env"].is_null());
    for (name, contents, oidc, environment, target) in contracts {
        let job = &jobs[name];
        assert_eq!(job["environment"].as_str(), Some(environment), "{name}");
        let permissions = job["permissions"].as_mapping().unwrap();
        assert_eq!(permissions.len(), if oidc { 2 } else { 1 }, "{name}");
        assert_eq!(job["permissions"]["contents"].as_str(), Some(contents));
        assert_eq!(
            job["permissions"]["id-token"].as_str(),
            if oidc { Some("write") } else { None }
        );
        assert!(
            job["env"].is_null(),
            "{name}: credentials must be step scoped"
        );
        if target.is_empty() {
            continue;
        }
        let step = task(job);
        let env = &step["env"];
        assert_eq!(env["RELEASE_TARGET"].as_str(), Some(target));
        assert_eq!(
            env["RELEASE_REQUEST"].as_str(),
            Some("${{ toJSON(inputs) }}")
        );
        for key in [
            "SOURCE_REPOSITORY",
            "SOURCE_BRANCH",
            "SOURCE_DEPLOY_KEY",
            "SOURCE_KNOWN_HOSTS",
        ] {
            assert_eq!(
                env[key].as_str(),
                Some(format!("${{{{ secrets.{key} }}}}").as_str()),
                "{name}:{key}"
            );
        }
        if name != "resolve" {
            for key in ["SOURCE_SHA", "VERSION", "BUILD_NUMBER"] {
                assert_eq!(
                    env[format!("RESOLVED_{key}").as_str()].as_str(),
                    Some(
                        format!(
                            "${{{{ needs.resolve.outputs.{} }}}}",
                            key.to_ascii_lowercase()
                        )
                        .as_str()
                    )
                );
            }
            for key in [
                "SOURCE_SUBMODULE_TOKEN",
                "SOURCE_SUBMODULE_DEPLOY_KEY_BASE64",
                "DIAGNOSTICS_PUBLIC_KEY",
            ] {
                assert_eq!(
                    env[key].as_str(),
                    Some(format!("${{{{ secrets.{key} }}}}").as_str())
                );
            }
            if name != "windows_sdk" {
                assert_eq!(
                    env["OMNITERM_VPN_PROVIDER_PUBLIC_KEY"].as_str(),
                    Some("${{ vars.OMNITERM_VPN_PROVIDER_PUBLIC_KEY }}")
                );
                for key in [
                    "LEAP_WINDOWS_SUITE_PUBLISHER_KEY_BASE64",
                    "LEAP_WINDOWS_SUITE_APPROVAL_KEY_BASE64",
                ] {
                    if name == "option1_signatures" {
                        assert!(env[key].is_null());
                    } else {
                        assert_eq!(
                            env[key].as_str(),
                            Some(format!("${{{{ vars.{key} }}}}").as_str())
                        );
                    }
                }
            } else {
                assert!(env["OMNITERM_VPN_PROVIDER_PUBLIC_KEY"].is_null());
            }
        } else {
            assert!(
                env["SOURCE_SUBMODULE_TOKEN"].is_null()
                    && env["SOURCE_SUBMODULE_DEPLOY_KEY_BASE64"].is_null()
                    && env["OMNITERM_VPN_PROVIDER_PUBLIC_KEY"].is_null()
            );
        }
        if name == "resolve" {
            assert!(env["STORAGE_CONFIG"].is_null() && env["BUILD_CONFIG"].is_null());
        } else if name == "verify" {
            assert_eq!(
                env["STORAGE_CONFIG"].as_str(),
                Some(
                    "${{ (!inputs.build_only || matrix.target == 'windows') && secrets.STORAGE_CONFIG || '' }}"
                )
            );
            assert_eq!(
                env["BUILD_CONFIG"].as_str(),
                Some("${{ !inputs.build_only && secrets.BUILD_CONFIG || '{}' }}")
            );
        } else if name == "windows_sdk" {
            assert_eq!(
                env["STORAGE_CONFIG"].as_str(),
                Some("${{ secrets.STORAGE_CONFIG }}")
            );
            assert!(env["BUILD_CONFIG"].is_null());
        } else {
            assert_eq!(
                env["STORAGE_CONFIG"].as_str(),
                Some("${{ secrets.STORAGE_CONFIG }}")
            );
            assert_eq!(
                env["BUILD_CONFIG"].as_str(),
                Some("${{ secrets.BUILD_CONFIG }}")
            );
        }
        let signing = match name {
            "verify" => Some(
                "${{ !inputs.build_only && (matrix.target == 'windows' && secrets.WINDOWS_SIGNING_CONFIG || matrix.target == 'macos' && secrets.MACOS_SIGNING_CONFIG || matrix.target == 'android' && secrets.ANDROID_SIGNING_CONFIG || matrix.target == 'ios' && secrets.IOS_SIGNING_CONFIG || '') || '' }}",
            ),
            "windows_download" | "external_windows_signing" => {
                Some("${{ secrets.WINDOWS_SIGNING_CONFIG }}")
            }
            "ios" | "apple_testflight" | "ios_delivery" | "apple_submission" => {
                Some("${{ secrets.IOS_SIGNING_CONFIG }}")
            }
            "package_signatures" | "option1_signatures" => {
                Some("${{ secrets.PACKAGE_SIGNING_CONFIG }}")
            }
            "downloads" => Some(
                "${{ matrix.target == 'macos' && secrets.MACOS_SIGNING_CONFIG || matrix.target == 'android' && secrets.ANDROID_SIGNING_CONFIG || '' }}",
            ),
            _ => None,
        };
        assert_eq!(env["SIGNING_CONFIG"].as_str(), signing, "{name}");
        if [
            "verify",
            "resolve",
            "integration",
            "managed_rtc_provider",
            "option1_signatures",
        ]
        .contains(&name)
        {
            assert!(env["GH_TOKEN"].is_null());
        }
        if name == "verify" {
            for (key, _) in env.as_mapping().unwrap() {
                assert!(!key.as_str().unwrap().starts_with("APP_STORE_CONNECT_"));
            }
        }
    }
    let approval = steps(&jobs["release_source_approval"])
        .iter()
        .find(|s| s["id"].as_str() == Some("approve"))
        .unwrap();
    for (key, value) in [
        ("RELEASE_REQUEST", "${{ toJSON(inputs) }}"),
        ("GITHUB_SHA", "${{ github.sha }}"),
        ("SOURCE_REPOSITORY", "omnisolo-llc/leapterm"),
        ("SOURCE_BRANCH", "main"),
    ] {
        assert_eq!(approval["env"][key].as_str(), Some(value));
    }
    assert!(
        approval["env"]["SOURCE_DEPLOY_KEY"].is_null()
            && approval["env"]["STORAGE_CONFIG"].is_null()
    );
    for key in [
        "APPROVED_RELEASE_SOURCE_SHA",
        "APPROVED_RELEASE_BUILDER_SHA",
    ] {
        assert!(approval["env"][key].is_null());
        assert!(task(&jobs["resolve"])["env"][key].is_null());
    }
}
fn matrix_values<'a>(job: &'a Value, key: &str) -> BTreeSet<&'a str> {
    job["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|r| r[key].as_str().unwrap())
        .collect()
}
#[test]
fn build_integration_installation_and_provider_matrices_remain_complete() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    let platforms = BTreeSet::from(["linux", "macos", "windows", "android", "ios", "web"]);
    for job in ["integration", "installation"] {
        assert_eq!(matrix_values(&jobs[job], "platform"), platforms);
    }
    assert_eq!(
        matrix_values(&jobs["downloads"], "target"),
        BTreeSet::from(["linux", "macos", "android", "web"])
    );
    assert_eq!(jobs["verify"]["strategy"]["max-parallel"].as_u64(), Some(6));
    let expression = jobs["verify"]["strategy"]["matrix"]["target"]
        .as_str()
        .unwrap();
    assert!(
        expression
            .contains("fromJSON('[\"linux\",\"windows\",\"macos\",\"android\",\"web\",\"ios\"]')")
    );
    let runner = jobs["verify"]["runs-on"].as_str().unwrap();
    for name in ["windows-2025", "macos-26", "ubuntu-24.04"] {
        assert!(runner.contains(name));
    }
    for row in jobs["installation"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
    {
        let platform = row["platform"].as_str().unwrap();
        let environment = if platform == "web" {
            "downloads".into()
        } else {
            format!("vpn-installation-{platform}")
        };
        assert_eq!(
            row["attestation_environment"].as_str(),
            Some(environment.as_str())
        );
        if platform != "web" {
            assert_eq!(
                row["vpn_profile_variable"].as_str(),
                Some(
                    format!(
                        "LEAP_VPN_INSTALLATION_PROFILE_{}",
                        platform.to_ascii_uppercase()
                    )
                    .as_str()
                )
            );
        }
    }
    let vpn = &jobs["vpn_container"];
    assert_eq!(
        matrix_values(vpn, "kernel_state"),
        BTreeSet::from(["present", "absent"])
    );
    for row in vpn["strategy"]["matrix"]["include"].as_sequence().unwrap() {
        // Separate hosted VMs retain independent, explicitly verified kernel states.
        assert_eq!(row["runner"].as_str(), Some("ubuntu-24.04"));
    }
    for text in [
        "docker info >/dev/null 2>&1",
        "present) test -d /sys/module/wireguard",
        "absent) test ! -d /sys/module/wireguard",
    ] {
        require_text(vpn, text);
    }
    assert_eq!(
        jobs["managed_rtc_provider"]["runs-on"].as_str(),
        Some("ubuntu-24.04")
    );
    let external = &jobs["external_tests"];
    assert_eq!(
        matrix_values(external, "platform"),
        BTreeSet::from(["linux", "macos", "windows"])
    );
    for row in external["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
    {
        let platform = row["platform"].as_str().unwrap();
        for (key, prefix) in [
            ("config_variable", "LEAP_EXTERNAL_CONFIG_"),
            (
                "candidate_guard_variable",
                "LEAP_EXTERNAL_CANDIDATE_GUARD_CONFIG_",
            ),
        ] {
            assert_eq!(
                row[key].as_str(),
                Some(format!("{prefix}{}", platform.to_ascii_uppercase()).as_str())
            );
        }
        let runner = match platform {
            "linux" => "ubuntu-24.04",
            "macos" => "macos-26",
            "windows" => "windows-2025",
            _ => unreachable!(),
        };
        assert_eq!(row["runner"].as_str(), Some(runner));
    }
}
#[test]
fn fixture_trust_files_and_publication_credentials_are_scoped_to_their_stages() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    let bindings = [
        (
            "integration",
            "LEAP_INTEGRATION_PLATFORM",
            "${{ matrix.platform }}",
        ),
        (
            "integration",
            "LEAP_INTEGRATION_DEVICE",
            "${{ vars[matrix.device_variable] || matrix.default_device }}",
        ),
        (
            "integration",
            "LEAP_INTEGRATION_DEFINES",
            "${{ vars[matrix.defines_variable] }}",
        ),
        (
            "installation",
            "LEAP_INSTALL_CONFIG",
            "${{ vars[matrix.config_variable] }}",
        ),
        (
            "installation",
            "LEAP_VPN_INSTALLATION_PROFILE_FILE",
            "${{ vars[matrix.vpn_profile_variable] || '' }}",
        ),
        (
            "installation",
            "LEAP_VPN_RECEIVER_TRUSTED_JWKS_JSON",
            "${{ vars.LEAP_VPN_RECEIVER_TRUSTED_JWKS_JSON }}",
        ),
        (
            "installation",
            "LEAP_VPN_TRUSTED_GATEWAY_POLICIES_JSON",
            "${{ vars.LEAP_VPN_TRUSTED_GATEWAY_POLICIES_JSON }}",
        ),
        (
            "managed_rtc_provider",
            "MANAGED_RTC_PROVIDER_ENVIRONMENT_FILE",
            "${{ vars.MANAGED_RTC_PROVIDER_ENVIRONMENT_FILE }}",
        ),
        (
            "managed_rtc_provider",
            "MANAGED_RTC_IDENTITY_FIXTURE_FILE",
            "${{ vars.MANAGED_RTC_IDENTITY_FIXTURE_FILE }}",
        ),
        (
            "vpn_container",
            "LEAP_VPN_E2E_KERNEL_MODULE_STATE",
            "${{ matrix.kernel_state }}",
        ),
        (
            "vpn_container",
            "OMNITERM_VPN_E2E_PROFILE_FILE",
            "${{ vars.OMNITERM_VPN_E2E_PROFILE_FILE }}",
        ),
        (
            "external_tests",
            "LEAP_EXTERNAL_CONFIG_FILE",
            "${{ vars[matrix.config_variable] }}",
        ),
        (
            "external_tests",
            "LEAP_EXTERNAL_CANDIDATE_GUARD_CONFIG_FILE",
            "${{ vars[matrix.candidate_guard_variable] }}",
        ),
        (
            "external_windows_signing",
            "LEAP_EXTERNAL_PLATFORM",
            "windows-signing",
        ),
        (
            "external_windows_signing",
            "LEAP_EXTERNAL_CANDIDATE_GUARD_CONFIG_FILE",
            "${{ vars.LEAP_EXTERNAL_CANDIDATE_GUARD_CONFIG_FILE }}",
        ),
    ];
    for (job, key, value) in bindings {
        assert_eq!(
            task(&jobs[job])["env"][key].as_str(),
            Some(value),
            "{job}:{key}"
        );
    }
    for role in ["CLIENT_BASE", "GATEWAY", "RELAY", "RECEIVER", "DNS"] {
        let key = format!("OMNITERM_VPN_E2E_{role}_IMAGE");
        assert_eq!(
            task(&jobs["vpn_container"])["env"][key.as_str()].as_str(),
            Some(format!("${{{{ vars.{key} }}}}").as_str())
        );
    }
    assert!(task(&jobs["external_tests"])["env"]["OMNITERM_VPN_E2E_PROFILE_FILE"].is_null());
    assert!(task(&jobs["external_tests"])["env"]["MANAGED_RTC_ACCEPTANCE_EVIDENCE"].is_null());
    for (name, job) in jobs.as_mapping().unwrap() {
        if name.as_str() == Some("release_source_approval") || name.as_str() == Some("publish") {
            continue;
        }
        if name.as_str() != Some("installation") {
            assert!(
                task(job)["env"]["LEAP_VPN_RECEIVER_TRUSTED_JWKS_JSON"].is_null()
                    && task(job)["env"]["LEAP_VPN_TRUSTED_GATEWAY_POLICIES_JSON"].is_null()
            );
        }
    }
    for key in [
        "LIVE_SHARE_SFU_ENABLED",
        "CLOUDFLARE_SFU_APP_ID",
        "CLOUDFLARE_SFU_APP_SECRET",
        "LIVE_SHARE_MOQ_ENABLED",
        "CLOUDFLARE_MOQ_ACCOUNT_ID",
        "CLOUDFLARE_MOQ_API_TOKEN",
        "LEAP_E2E_EDGE_URL",
        "LEAP_E2E_IDENTITY_URL",
        "LEAP_E2E_IDENTITY_WORKLOAD_TOKEN",
        "LEAP_E2E_OIDC_ISSUER_URL",
        "LEAP_E2E_OIDC_AUTHORIZATION_ENDPOINT",
        "LEAP_E2E_OIDC_REDIRECT_URI",
        "LEAP_E2E_OIDC_CLIENT_ID",
        "LEAP_E2E_OIDC_EXPECTED_SUBJECT_ID",
        "LEAP_E2E_OIDC_TENANT_ID",
        "LEAP_E2E_OIDC_STORAGE_STATE",
    ] {
        assert!(task(&jobs["external_tests"])["env"][key].is_null());
    }
    assert!(jobs["production_oidc"].is_null());
    require_text(&jobs["external_tests"], "RELEASE_METADATA_READ_TOKEN");
}
#[test]
fn all_release_evidence_is_encrypted_and_retained_through_selected_private_storage() {
    let w = workflow("release");
    let mut candidate_exchanges = BTreeSet::new();
    for (name, job) in w["jobs"].as_mapping().unwrap() {
        let definition = serde_json::to_value(job).unwrap();
        for step in steps(job) {
            if let Some(action) = step["uses"].as_str() {
                if action.starts_with("actions/upload-artifact@")
                    || action.starts_with("actions/download-artifact@")
                {
                    let kind =
                        omni_release_launcher::runner_policy::reviewed_public_candidate_exchange(
                            "release.yml",
                            name.as_str().unwrap(),
                            &definition,
                            &serde_json::to_value(step).unwrap(),
                        )
                        .expect(
                            "only the closed public candidate exchange may use Actions storage",
                        );
                    candidate_exchanges.insert((name.as_str().unwrap(), kind));
                }
                assert!(
                    !action.starts_with("actions/cache")
                        || omni_release_launcher::runner_policy::reviewed_windows_sdk_cache(
                            "release.yml",
                            name.as_str().unwrap(),
                            &definition,
                            &serde_json::to_value(step).unwrap(),
                        ),
                    "{name:?}: forbidden Actions storage"
                );
            }
            let env = &step["env"];
            let Some(kind) = env["RELEASE_ARTIFACT_KIND"].as_str() else {
                continue;
            };
            assert_eq!(
                step["run"].as_str(),
                Some("bash ci/native-release/run.sh retain-artifacts")
            );
            assert_eq!(
                env["STORAGE_CONFIG"].as_str(),
                Some("${{ secrets.STORAGE_CONFIG }}")
            );
            assert_eq!(
                env["RESOLVED_SOURCE_SHA"].as_str(),
                Some("${{ needs.resolve.outputs.source_sha }}")
            );
            for credential in [
                "SIGNING_CONFIG",
                "BUILD_CONFIG",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "DIAGNOSTICS_PUBLIC_KEY",
            ] {
                assert!(env[credential].is_null(), "{name:?}:{credential}");
            }
            assert!(step["with"].is_null());
            if kind == "evaluation" {
                assert_eq!(name.as_str(), Some("verify"));
                assert_eq!(
                    env["RELEASE_ARTIFACT_SCOPE"].as_str(),
                    Some("verify-${{ matrix.target }}")
                );
                require_text(
                    step,
                    "inputs.preview_windows_self_sign && matrix.target == 'windows'",
                );
                require_text(step, "success()");
            } else {
                assert_eq!(kind, "diagnostics");
                assert_eq!(step["if"].as_str(), Some("${{ always() }}"));
            }
        }
        if !["release_source_approval", "resolve"].contains(&name.as_str().unwrap()) {
            assert_eq!(
                steps(job)
                    .iter()
                    .filter(|s| s["env"]["RELEASE_ARTIFACT_KIND"].as_str() == Some("diagnostics"))
                    .count(),
                1
            );
        }
    }
    assert!(candidate_exchanges.is_empty());
    assert!(
        task(&w["jobs"]["verify"])["env"]["WINDOWS_PREVIEW_OUTPUT_DIR"]
            .as_str()
            .unwrap()
            .contains("inputs.preview_windows_self_sign && matrix.target == 'windows'")
    );
    assert!(
        !serde_yaml::to_string(&w["jobs"]["publish"])
            .unwrap()
            .contains("preview_windows_self_sign")
    );
}

#[test]
fn windows_application_jobs_consume_the_same_private_source_bound_sdk() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    let sdk = &jobs["windows_sdk"];
    assert_eq!(sdk["runs-on"].as_str(), Some("ubuntu-24.04"));
    assert_eq!(
        task(sdk)["run"].as_str(),
        Some("bash ci/native-release/run.sh windows-sdk")
    );
    assert_eq!(
        sdk["outputs"]["manifest_sha256"].as_str(),
        Some("${{ steps.sdk.outputs.manifest_sha256 }}")
    );
    for name in ["integration", "verify", "windows_download"] {
        assert!(needs(&jobs[name]).contains("windows_sdk"));
        assert_eq!(
            task(&jobs[name])["env"]["OMNITERM_WINDOWS_SDK_MANIFEST_SHA256"].as_str(),
            Some("${{ needs.windows_sdk.outputs.manifest_sha256 }}")
        );
    }
    require_text(
        sdk,
        "inputs.verify_target == 'all' || inputs.verify_target == 'windows'",
    );
    require_text(
        &jobs["verify"],
        "needs.windows_sdk.result == 'skipped' && inputs.verify_target != 'all' && inputs.verify_target != 'windows'",
    );
    let policy: serde_json::Value =
        serde_json::from_str(&read("ci/standard-runner-policy.json")).unwrap();
    assert_eq!(policy["prohibit_actions_storage"], true);
}
#[test]
fn native_agent_matrix_pin_wix_and_complete_hash_check_precede_artifact_retention() {
    let w = workflow("omni-agent");
    let job = &w["jobs"]["native-agent"];
    assert_eq!(
        matrix_values(job, "platform"),
        omni_release_launcher::agent::PLATFORMS
            .iter()
            .copied()
            .collect()
    );
    let s = steps(job);
    let handoff = s
        .iter()
        .position(|v| {
            v["run"]
                .as_str()
                .is_some_and(|r| r.contains("run.sh verify-agent-handoff"))
        })
        .unwrap();
    let upload = s
        .iter()
        .position(|v| v["env"]["RELEASE_ARTIFACT_KIND"].as_str() == Some("agent-packages"))
        .unwrap();
    assert!(handoff < upload);
    assert_eq!(
        s[upload]["run"].as_str(),
        Some("bash ci/native-release/run.sh retain-artifacts")
    );
    assert_eq!(
        s[upload]["env"]["STORAGE_CONFIG"].as_str(),
        Some("${{ secrets.LEAP_AGENT_STORAGE_CONFIG }}")
    );
    assert_eq!(
        s[upload]["env"]["RESOLVED_SOURCE_SHA"].as_str(),
        Some("${{ steps.approved.outputs.source_sha }}")
    );
    assert_eq!(
        s[upload]["env"]["RELEASE_ARTIFACT_SCOPE"].as_str(),
        Some("${{ matrix.artifact_scope }}")
    );
    for step in s {
        if let Some(action) = step["uses"].as_str() {
            assert!(
                !action.starts_with("actions/upload-artifact@")
                    && !action.starts_with("actions/download-artifact@")
                    && !action.starts_with("actions/cache")
            );
        }
        if step["env"]["RELEASE_ARTIFACT_KIND"].as_str().is_some() {
            for key in [
                "SIGNING_CONFIG",
                "DIAGNOSTICS_PUBLIC_KEY",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "BUILD_CONFIG",
            ] {
                assert!(step["env"][key].is_null());
            }
        }
    }
    for row in job["strategy"]["matrix"]["include"].as_sequence().unwrap() {
        let platform = row["platform"].as_str().unwrap();
        assert_eq!(
            row["artifact_scope"].as_str(),
            Some(format!("agent-{}", platform.replace('_', "-")).as_str())
        );
        assert!(
            omni_release_launcher::runner_policy::RUNNERS
                .contains(&row["runner"].as_str().unwrap())
        );
    }
    assert!(
        s.iter()
            .any(|v| v["run"].as_str() == Some("bash ci/native-release/run.sh agent-source"))
    );
    assert_eq!(
        task(job)["run"].as_str(),
        Some("bash ci/native-release/run.sh agent-run")
    );
    for extension in [
        "WixToolset.UI.wixext",
        "WixToolset.BootstrapperApplications.wixext",
    ] {
        require_text(job, &format!("extension add -g {extension}/6.0.2"));
    }
    assert_eq!(
        task(job)["env"]["LEAP_AGENT_OUTPUT"].as_str(),
        Some("${{ runner.temp }}/agent-release")
    );
}
#[test]
fn pinned_actions_sdk_versions_and_real_relay_suites_remain_required() {
    let w = workflow("release");
    let jobs = &w["jobs"];
    for (_, job) in jobs.as_mapping().unwrap() {
        for step in steps(job) {
            if let Some(action) = step["uses"].as_str() {
                let (_, sha) = action.split_once('@').unwrap();
                assert_eq!(sha.len(), 40);
                assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()));
            }
            if let Some(version) = step["with"]["node-version"].as_str() {
                assert_eq!(version, "24.21.0");
            }
            if let Some(version) = step["with"]["java-version"].as_str() {
                assert_eq!(version, "17.0.20+101");
            }
        }
    }
    for command in [
        "npm ci --prefix relay/native",
        "node --test --test-concurrency=1 ci/test_native_relay_contract.mjs",
        "npm ci --ignore-scripts --prefix relay/moq",
        "npm run native-build --prefix relay/moq",
        "npm test --prefix relay/moq",
        "build-essential cmake libicu-dev",
    ] {
        require_text(&jobs["validate"], command);
    }
    let contracts = workflow("contracts");
    assert_eq!(
        contracts["jobs"]["contracts"]["strategy"]["matrix"]["runner"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["ubuntu-24.04", "windows-2025", "macos-26"])
    );
    for (job, commands) in [
        (
            "first-party-moq",
            vec![
                "npm ci --ignore-scripts --prefix relay/moq",
                "npm run native-build --prefix relay/moq",
                "npm test --prefix relay/moq",
                "build-essential cmake libicu-dev",
            ],
        ),
        (
            "native-relay-contract",
            vec![
                "npm ci --prefix relay/native",
                "node --test --test-concurrency=1 ci/test_native_relay_contract.mjs",
            ],
        ),
    ] {
        for c in commands {
            require_text(&contracts["jobs"][job], c);
        }
    }
    for job in ["windows_download", "external_windows_signing"] {
        for c in [
            "74bd7d27e6ce1051409c38d9b46bc8df0400ecd643d51ffbf2ac00869061e40b",
            "LEAP_WINDOWS_ARTIFACT_SIGNING_DLIB=$dlib",
        ] {
            require_text(&jobs[job], c);
        }
    }
}
#[test]
fn real_external_host_prerequisites_are_verified_before_native_execution() {
    let w = workflow("release");
    let s = steps(&w["jobs"]["external_tests"]);
    let index = |text: &str| {
        s.iter()
            .position(|v| v["run"].as_str().is_some_and(|r| r.contains(text)))
            .unwrap()
    };
    let archive = index("sudo -n apt-get update");
    let provision = index("sudo -n apt-get install -y --no-install-recommends");
    let verify = index("pkg-config --exists gio-unix-2.0");
    let execute = index("bash ci/native-release/run.sh run");
    assert!(archive < provision && provision < verify && verify < execute);
    for package in [
        "g++",
        "g++-mingw-w64-x86-64",
        "gcc-mingw-w64-x86-64",
        "libglib2.0-dev",
        "openjdk-17-jdk-headless",
        "pkg-config",
    ] {
        require_text(&s[provision], package);
    }
    for check in [
        "command -v \"$tool\"",
        "x86_64-w64-mingw32-g++",
        "x86_64-w64-mingw32-gcc",
        "gpgconf",
        "javac",
        "gpgv --status-fd 1 --keyring \"$keyring\" \"$metadata\"",
        "F6ECB3762474EDA9D21B7022871920D1991BC93C",
        "VALIDSIG ${ubuntu_archive_signer}",
    ] {
        require_text(&s[verify], check);
    }
    for check in [
        "ubuntu-archive-keyring",
        "dpkg-query -S \"$keyring\"",
        "dpkg --verify ubuntu-keyring",
    ] {
        require_text(&s[archive], check);
    }
    let ruby = s
        .iter()
        .position(|v| {
            v["uses"]
                .as_str()
                .is_some_and(|a| a.starts_with("ruby/setup-ruby@"))
        })
        .unwrap();
    assert!(ruby < execute);
    assert_eq!(s[ruby]["with"]["ruby-version"].as_str(), Some("3.4.7"));
}
#[test]
fn release_defaults_and_protected_approval_documentation_remain_explicit() {
    let w = workflow("release");
    let inputs = &w["on"]["workflow_dispatch"]["inputs"];
    for key in ["source_sha", "builder_sha"] {
        assert_eq!(inputs[key]["required"].as_bool(), Some(false));
        assert_eq!(inputs[key]["default"].as_str(), Some(""));
    }
    assert_eq!(inputs["version"]["default"].as_str(), Some("0.1.0"));
    assert_eq!(inputs["build_number"]["required"].as_bool(), Some(true));
    assert!(inputs["build_number"]["default"].is_null());
    assert!(
        inputs["build_number"]["description"]
            .as_str()
            .unwrap()
            .contains("1-9999")
    );
    assert!(
        inputs["include_selfhost"]["description"]
            .as_str()
            .unwrap()
            .contains("only build-only validation may omit it")
    );
    let docs = read("README.md");
    for text in [
        "LeapTerm client downloads",
        "self-hosted relay kit",
        "# Omni Agent Native Builds",
    ] {
        assert!(docs.contains(text), "{text}");
    }
    for forbidden in [
        "omnisolo-llc/leapterm/releases",
        "release-source-approval",
        "APPROVED_RELEASE_SOURCE_SHA",
        "LEAP_EXTERNAL_CONFIG_LINUX",
    ] {
        assert!(!docs.contains(forbidden), "README leaked {forbidden}");
    }
    assert!(
        !repository()
            .join("ci/approved_release_source.json")
            .exists()
    );
}
#[test]
fn public_moq_cutoff_patch_and_locked_rebuild_contract_is_preserved() {
    let package: serde_json::Value = serde_json::from_str(&read("relay/moq/package.json")).unwrap();
    assert_eq!(
        package["scripts"]["native-build"],
        "node scripts/build-patched-webtransport.mjs"
    );
    assert!(package["scripts"]["postinstall"].is_null());
    assert_eq!(read("relay/moq/.npmrc").trim(), "ignore-scripts=true");
    let builder = read("relay/moq/scripts/build-patched-webtransport.mjs");
    for text in [
        "212ef743f0cf52adb234d60d5b41c48257e967b4",
        "80bf9559d3a4c08dde4b85abc46d190a88ffef64",
        "npm_tarball_integrity",
        "patch_sha256",
        "'--unidiff-zero'",
        "build_${process.platform}_${process.arch}/Release/webtransport.node",
        "package-lock.json",
        "join(packageRoot, 'node_modules', '.bin')",
        "binary_sha256",
        "npm_config_build_from_source: 'true'",
        "cmake-js/bin/cmake-js",
        "--CDgtest_build_tests=OFF",
        "--CDCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE",
        "--CDCMAKE_DISABLE_FIND_PACKAGE_Python=TRUE",
        "nativeBuildPath(adapterRoot)",
        "requireLoadedAddon",
        "webtransport-client-close.patch",
        "client_patch_sha256=",
    ] {
        assert!(builder.contains(text), "{text}");
    }
    assert!(!builder.contains("'build.js', 'install'"));
    assert_eq!(
        read("relay/moq/patches/quiche-server-close-ack.patch")
            .matches("+    MaybeNotifyClose();")
            .count(),
        2
    );
    let patch = read("relay/moq/patches/webtransport-server-connection-close.patch");
    for text in [
        "Http3ServerSession::OnConnectionClosed",
        "(*itty).second->RemoveVisitorRemoveVisitor();",
        "session_closed_ = false",
    ] {
        assert!(patch.contains(text));
    }
}
