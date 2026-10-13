use omni_release_launcher::{Environment, agent};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
#[test]
fn pinned_source_command_exports_validated_identity_without_checkout() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("output");
    fs::write(&output, "").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("agent-source")
        .env_clear()
        .env("GITHUB_OUTPUT", &output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let pin = agent::approved_source().unwrap();
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        format!(
            "source_sha={}\nsource_branch={}\nversion={}\n",
            pin.source_sha, pin.source_branch, pin.version
        )
    );
}

#[test]
fn complete_six_platform_handoffs_verify_actual_bytes_and_reject_mutations() {
    for platform in agent::PLATFORMS {
        let temp = tempfile::tempdir().unwrap();
        let names = agent::package_names("0.1.1", platform).unwrap();
        let bytes = b"actual fixture bytes";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let assets: Vec<_> = names
            .iter()
            .map(|name| {
                fs::write(temp.path().join(name), bytes).unwrap();
                json!({"name":name,"size":bytes.len(),"sha256":digest})
            })
            .collect();
        let payload: serde_json::Map<_, _> = agent::payload_names(platform)
            .iter()
            .map(|name| (name.to_string(), json!({"size":1,"sha256":"a".repeat(64)})))
            .collect();
        let manifest = temp.path().join(format!("packages-{platform}.json"));
        let value = json!({"schema":1,"version":"0.1.1","platform":platform,"platform_signing":"not_performed","payload":payload,"assets":assets});
        fs::write(&manifest, value.to_string()).unwrap();
        assert_eq!(
            agent::verify_handoff(temp.path(), "0.1.1", platform).unwrap(),
            names.len()
        );
        let asset = temp.path().join(names.iter().next().unwrap());
        fs::write(&asset, b"changed bytes").unwrap();
        assert!(agent::verify_handoff(temp.path(), "0.1.1", platform).is_err());
        fs::write(&asset, bytes).unwrap();
        fs::write(temp.path().join("private.log"), "private").unwrap();
        assert!(agent::verify_handoff(temp.path(), "0.1.1", platform).is_err());
        fs::remove_file(temp.path().join("private.log")).unwrap();
        fs::remove_file(&asset).unwrap();
        assert!(agent::verify_handoff(temp.path(), "0.1.1", platform).is_err());
        fs::write(&asset, bytes).unwrap();
        fs::write(
            &manifest,
            value
                .to_string()
                .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
        )
        .unwrap();
        assert!(agent::verify_handoff(temp.path(), "0.1.1", platform).is_err());
        for fault in [
            "private-field",
            "false-signing",
            "duplicate-asset",
            "wrong-version",
            "boolean-size",
            "nested-duplicate",
        ] {
            let mut invalid = value.clone();
            match fault {
                "private-field" => invalid["private_diagnostics"] = json!("private"),
                "false-signing" => invalid["platform_signing"] = json!("verified"),
                "duplicate-asset" => {
                    let duplicate = invalid["assets"][0].clone();
                    invalid["assets"].as_array_mut().unwrap().push(duplicate);
                }
                "wrong-version" => invalid["version"] = json!("0.1.0"),
                "boolean-size" => invalid["assets"][0]["size"] = json!(true),
                "nested-duplicate" => {}
                _ => unreachable!(),
            }
            let mut raw = invalid.to_string();
            if fault == "nested-duplicate" {
                raw = raw.replacen("\"size\":1", "\"size\":0,\"size\":1", 1);
            }
            fs::write(&manifest, raw).unwrap();
            assert!(
                agent::verify_handoff(temp.path(), "0.1.1", platform).is_err(),
                "{fault}"
            );
        }
        fs::write(&manifest, value.to_string()).unwrap();
        #[cfg(unix)]
        {
            fs::remove_file(&asset).unwrap();
            std::os::unix::fs::symlink(&manifest, &asset).unwrap();
            assert!(agent::verify_handoff(temp.path(), "0.1.1", platform).is_err());
        }
    }
}
#[test]
fn exact_pinned_agent_authority_admits_all_platforms_and_denies_effectful_requests() {
    let pin = agent::approved_source().unwrap();
    for platform in agent::PLATFORMS {
        let target = agent::target(platform).unwrap();
        let env=Environment::from([("GITHUB_ACTIONS".into(),"true".into()),("GITHUB_EVENT_NAME".into(),"workflow_dispatch".into()),("GITHUB_REPOSITORY".into(),"omnisolo-llc/omniterm-release".into()),("GITHUB_REF".into(),"refs/heads/main".into()),("GITHUB_WORKFLOW_REF".into(),"omnisolo-llc/omniterm-release/.github/workflows/omni-agent.yml@refs/heads/main".into()),("GITHUB_SHA".into(),"b".repeat(40)),("GITHUB_RUN_ID".into(),"1".into()),("GITHUB_RUN_ATTEMPT".into(),"1".into()),("SOURCE_REPOSITORY".into(),"omnisolo-llc/omniterm".into()),("SOURCE_BRANCH".into(),pin.source_branch.clone()),("RESOLVED_SOURCE_SHA".into(),pin.source_sha.clone()),("OMNI_AGENT_PLATFORM".into(),platform.to_string()),("RELEASE_TARGET".into(),target.into()),("RELEASE_REQUEST".into(),json!({"source_sha":pin.source_sha,"version":pin.version,"build_number":"1","build_only":true,"ios_action":"skip","automatic_release":false,"include_selfhost":true}).to_string())]);
        agent::validate_authority(&env).unwrap();
        for (key, value) in [
            ("GITHUB_WORKFLOW_REF", "other"),
            ("SOURCE_REPOSITORY", "other/private"),
            ("SOURCE_BRANCH", "main"),
            ("SOURCE_ENTRYPOINT", "legacy"),
            ("GITHUB_RUN_ID", "0"),
            ("RESOLVED_SOURCE_SHA", "bad"),
            ("RELEASE_TARGET", "publish"),
        ] {
            let mut bad = env.clone();
            bad.insert(key.into(), value.into());
            assert!(agent::validate_authority(&bad).is_err(), "{key}");
        }
        for (key, value) in [
            ("build_only", json!(false)),
            ("ios_action", json!("upload")),
            ("automatic_release", json!(true)),
            ("source_sha", json!("a".repeat(40))),
            ("extra", json!(true)),
        ] {
            let mut bad = env.clone();
            let mut request: serde_json::Value =
                serde_json::from_str(&env["RELEASE_REQUEST"]).unwrap();
            request[key] = value;
            bad.insert("RELEASE_REQUEST".into(), request.to_string());
            assert!(agent::validate_authority(&bad).is_err(), "{key}");
        }
    }
}
#[test]
fn package_identity_cannot_select_paths_or_exceed_msi_bounds() {
    for version in ["../../escape", "01.2.3", "256.1.1", "1.256.1", "1.1.65536"] {
        assert!(agent::package_names(version, "windows-x86_64").is_err());
    }
    assert!(agent::package_names("1.0.0", "../../escape").is_err());
}
