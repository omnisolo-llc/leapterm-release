//! A public synthetic CLI, real Cargo compilation, real Git commits and gitlinks.
//! The transport adapter maps canonical remote operations to local fixture repos.
#![cfg(unix)]
use omni_release_launcher::{Environment, input::RELEASE_TARGETS};
use serde_json::json;
use std::{fs, path::Path, process::Command};
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn init(path: &Path) {
    fs::create_dir(path).unwrap();
    git(path, &["init", "-q", "-b", "main"]);
    git(path, &["config", "user.name", "Fixture"]);
    git(path, &["config", "user.email", "fixture@example.invalid"]);
    git(path, &["config", "core.autocrlf", "false"]);
}
fn script(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\"'\"'"))
}
const CLI: &str = r#"
fn main(){
    use std::{env,fs,path::Path};
    let args:Vec<String>=env::args().skip(1).collect();
    assert_eq!(args.len(),5);assert_eq!(args[1],"--root");assert_eq!(args[3],"--work-dir");
    assert!(args[0]=="run" || args[0]=="agent-run");
    let source=Path::new(&args[2]);let work=Path::new(&args[4]);
    assert_eq!(env::var("SOURCE").unwrap(),args[2]);
    assert_eq!(env::var("PUBLIC_BUILDER_SHA").unwrap(),env::var("GITHUB_SHA").unwrap());
    assert_eq!(env::var("GITHUB_RUN_ATTEMPT").unwrap(),"2");
    assert_eq!(env::var("RELEASE_INTEGRATION_SOURCE_REPOSITORY").unwrap(),"omnisolo-llc/leapterm");
    assert_eq!(env::var("RELEASE_INTEGRATION_SOURCE_REF").unwrap(),"refs/heads/main");
    let request=env::var("RELEASE_REQUEST").unwrap();assert!(!request.contains("builder_sha") && !request.contains("verify_target") && !request.contains("preview_windows_self_sign"));
    for key in ["SOURCE_DEPLOY_KEY","SOURCE_KNOWN_HOSTS","SOURCE_SUBMODULE_TOKEN","SOURCE_SUBMODULE_DEPLOY_KEY_BASE64","GITHUB_OUTPUT","GITHUB_ENV","NODE_OPTIONS","RUSTFLAGS"]{assert!(env::var_os(key).is_none(),"{key}");}
    for name in ["identity","known_hosts","website-identity"]{assert!(!source.parent().unwrap().join(name).exists());}
    assert!(source.join("leapterm-release/payload").is_file());
    assert_eq!(env::var("SIGNING_CONFIG").unwrap(),"synthetic-signing-config");
    assert_eq!(env::var("STORAGE_CONFIG").unwrap(),"synthetic-storage-config");
    let target=env::var("RELEASE_TARGET").unwrap();
    if request.contains("\"build_only\":false") && ["linux","windows","macos","android","ios","web","publish"].contains(&target.as_str()){assert_eq!(env::var("DIAGNOSTICS_PUBLIC_KEY").unwrap(),"unqualified-local-recipient");}
    if target=="publish"{assert!(env::var("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE").unwrap().ends_with("unqualified-operator-inputs.json"));}else{assert!(env::var_os("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE").is_none());}
    if args[0]=="agent-run"{let platform=env::var("LEAP_AGENT_PLATFORM").unwrap();let target=if platform.starts_with("darwin-"){"macos"}else if platform.starts_with("windows-"){"windows"}else{"linux"};assert_eq!(env::var("RELEASE_TARGET").unwrap(),target);fs::write(Path::new(&env::var("LEAP_AGENT_OUTPUT").unwrap()).join("synthetic-handoff"),platform).unwrap();}
    fs::write(work.join("handoff"),format!("{}\n{}\n{}",env::var("RELEASE_TARGET").unwrap(),request,env::var("SOURCE").unwrap())).unwrap();
    println!("private synthetic compiler and source output");
    if env::var("LEAP_FIXTURE_FAIL").is_ok(){std::process::exit(9);}
}
"#;
const BUILD: &str = r#"
fn main(){
    for key in ["SOURCE_DEPLOY_KEY","SOURCE_SUBMODULE_TOKEN","SOURCE_SUBMODULE_DEPLOY_KEY_BASE64","SIGNING_CONFIG","STORAGE_CONFIG","GH_TOKEN","GITHUB_TOKEN","SOURCE","RELEASE_REQUEST","RUSTFLAGS","GITHUB_OUTPUT","DIAGNOSTICS_PUBLIC_KEY","PRIVATE_FINAL_ARCHIVE_INPUTS_FILE"] {assert!(std::env::var_os(key).is_none(),"{key}");}
    assert!(std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default().is_empty());
    for file in ["identity","known_hosts","website-identity"]{assert!(!std::path::Path::new(file).exists());}
    assert!(std::env::var("CARGO_BUILD_JOBS").unwrap().parse::<usize>().is_ok_and(|n| (1..=64).contains(&n)));
    println!("private synthetic build-script output");
}
"#;
struct Fixture {
    _temp: tempfile::TempDir,
    source: std::path::PathBuf,
    runner: std::path::PathBuf,
    env: Environment,
    sha: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let builder = root.join("builder");
        init(&builder);
        fs::write(builder.join("payload"), "public synthetic builder").unwrap();
        git(&builder, &["add", "."]);
        git(&builder, &["commit", "-qm", "builder fixture"]);
        let builder_sha = git(&builder, &["rev-parse", "HEAD"]);
        let source = root.join("fixture-source");
        init(&source);
        let tools = source.join("tools/release-cli");
        fs::create_dir_all(tools.join("src")).unwrap();
        fs::write(tools.join("Cargo.toml"),"[package]\nname = \"omni-release\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[workspace]\n").unwrap();
        fs::write(
            tools.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"omni-release\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(tools.join("src/main.rs"), CLI).unwrap();
        fs::write(tools.join("build.rs"), BUILD).unwrap();
        git(
            &source,
            &[
                "submodule",
                "add",
                "-q",
                builder.to_str().unwrap(),
                "leapterm-release",
            ],
        );
        git(
            &source,
            &[
                "config",
                "--file",
                ".gitmodules",
                "submodule.leapterm-release.url",
                omni_release_launcher::source::PUBLIC_URL,
            ],
        );
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "private transport fixture"]);
        let sha = git(&source, &["rev-parse", "HEAD"]);
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let transport = format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
args=("$@")
for ((i=0;i<${{#args[@]}};i++)); do
  if [[ "${{args[i]}}" == fetch ]]; then
    for ((j=i+1;j<${{#args[@]}};j++)); do
      if [[ "${{args[j]}}" == origin ]]; then args[j]={source}; break; fi
    done
  fi
  if [[ "${{args[i]}}" == submodule.leapterm-release.url=* ]]; then args[i]=submodule.leapterm-release.url={builder}; fi
done
/usr/bin/git -c protocol.file.allow=always "${{args[@]}}"
if [[ -f leapterm-release/payload ]]; then /usr/bin/git -C leapterm-release remote set-url origin https://github.com/omnisolo-llc/leapterm-release.git; fi
"#,
            source = quoted(&source),
            builder = quoted(&builder)
        );
        script(&bin.join("git"), &transport);
        // Only toolchain installation is synthetic; Cargo actually builds/tests the locked fixture.
        script(&bin.join("rustup"), "#!/bin/sh\nexit 0\n");
        let cargo = std::env::var("CARGO").unwrap();
        script(
            &bin.join("cargo"),
            &format!(
                "#!/bin/sh\n[ \"$1\" = '+1.95.0' ] || exit 98\nshift\n'{}' \"$@\" >{} 2>&1\nstatus=$?\ncat {}\nexit \"$status\"\n",
                cargo,
                quoted(&root.join("cargo-fixture.log")),
                quoted(&root.join("cargo-fixture.log"))
            ),
        );
        for forbidden in ["python", "python3", "pip", "pip3"] {
            script(&bin.join(forbidden), "#!/bin/sh\nexit 97\n");
        }
        let runner = root.join("runner");
        fs::create_dir(&runner).unwrap();
        let output = root.join("output");
        fs::write(&output, "").unwrap();
        let env=Environment::from([
            ("PATH".into(),format!("{}:{}",bin.display(),std::env::var("PATH").unwrap())),("HOME".into(),std::env::var("HOME").unwrap()),("RUSTUP_HOME".into(),std::env::var("RUSTUP_HOME").unwrap_or_else(|_|format!("{}/.rustup",std::env::var("HOME").unwrap()))),
            ("RUNNER_TEMP".into(),runner.to_str().unwrap().into()),("TMPDIR".into(),root.to_str().unwrap().into()),("GITHUB_OUTPUT".into(),output.to_str().unwrap().into()),
            ("GITHUB_ACTIONS".into(),"true".into()),("GITHUB_EVENT_NAME".into(),"workflow_dispatch".into()),("GITHUB_REPOSITORY".into(),"omnisolo-llc/leapterm-release".into()),("GITHUB_REF".into(),"refs/heads/main".into()),("GITHUB_WORKFLOW_REF".into(),"omnisolo-llc/leapterm-release/.github/workflows/release.yml@refs/heads/main".into()),("GITHUB_SHA".into(),builder_sha.clone()),("GITHUB_RUN_ID".into(),"42".into()),("GITHUB_RUN_ATTEMPT".into(),"2".into()),
            ("SOURCE_REPOSITORY".into(),"omnisolo-llc/leapterm".into()),("SOURCE_BRANCH".into(),"main".into()),("SOURCE_DEPLOY_KEY".into(),"-----BEGIN SYNTHETIC PRIVATE KEY-----\nfixture\n-----END SYNTHETIC PRIVATE KEY-----".into()),("SOURCE_KNOWN_HOSTS".into(),"synthetic-host fixture".into()),("SOURCE_SUBMODULE_DEPLOY_KEY_BASE64".into(),base64::Engine::encode(&base64::engine::general_purpose::STANDARD,"-----BEGIN SYNTHETIC PRIVATE KEY-----\nfixture\n-----END SYNTHETIC PRIVATE KEY-----")),
            ("SOURCE_SUBMODULE_TOKEN".into(),"synthetic-read-token".into()),("SIGNING_CONFIG".into(),"synthetic-signing-config".into()),("STORAGE_CONFIG".into(),"synthetic-storage-config".into()),("BUILD_CONFIG".into(),r#"{"LEAP_ENABLE_VPN":"true"}"#.into()),("APPROVED_RELEASE_SOURCE_SHA".into(),sha.clone()),("APPROVED_RELEASE_BUILDER_SHA".into(),builder_sha),
            ("OMNITERM_VPN_PROVIDER_PUBLIC_KEY".into(),base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,[1u8;32])),
            // Forwarding placeholders only: genuine native archive retention would refuse these inputs.
            ("DIAGNOSTICS_PUBLIC_KEY".into(),"unqualified-local-recipient".into()),
            ("PRIVATE_FINAL_ARCHIVE_INPUTS_FILE".into(),root.join("unqualified-operator-inputs.json").to_str().unwrap().into()),
            ("GH_TOKEN".into(),"synthetic-scoped-token".into()),("RUSTFLAGS".into(),"untrusted compiler setting".into()),("NODE_OPTIONS".into(),"untrusted runtime setting".into())
        ]);
        Self {
            _temp: temp,
            source,
            runner,
            env,
            sha,
        }
    }
    fn run(
        &self,
        command: &str,
        target: &str,
        build_only: bool,
        fail: bool,
    ) -> std::process::Output {
        let mut env = self.env.clone();
        env.insert("RELEASE_TARGET".into(), target.into());
        env.insert("RELEASE_REQUEST".into(),json!({"build_only":build_only,"source_sha":self.sha,"builder_sha":env["GITHUB_SHA"],"version":"1.2.3","build_number":"42","ios_action":if build_only{"skip"}else{"submit"}}).to_string());
        if target != "resolve" {
            env.insert("RESOLVED_SOURCE_SHA".into(), self.sha.clone());
        }
        if fail {
            env.insert("LEAP_FIXTURE_FAIL".into(), "true".into());
        }
        Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
            .arg(command)
            .env_clear()
            .envs(env)
            .output()
            .unwrap()
    }
}
#[test]
fn actual_ci_dispatch_uses_distinct_request_and_cleans_privileged_environment() {
    use omni_release_launcher::{ci_request::SourceCiRequest, launch::build_and_dispatch_ci};
    let fixture = Fixture::new();
    let cli = r#"fn main() {
        use std::{env,fs,path::Path};
        let args:Vec<_>=env::args().skip(1).collect();
        assert_eq!(args.len(),7);assert_eq!(args[0],"ci");assert_eq!(args[1],"--root");assert_eq!(args[3],"--work-dir");assert_eq!(args[5],"--request");
        let value=fs::read_to_string(&args[6]).unwrap();assert_eq!(value,env::var("SOURCE_CI_REQUEST").unwrap());
        assert!(!value.contains("version") && !value.contains("ios_action"));
        assert_eq!(env::var("CARGO_BUILD_JOBS").unwrap(),"2");
        for key in ["GH_TOKEN","GITHUB_TOKEN","PRIVATE_RELEASE_TOKEN","SOURCE_DEPLOY_KEY","SOURCE_METADATA_READ_TOKEN","SOURCE_SUBMODULE_TOKEN","SOURCE_SUBMODULE_DEPLOY_KEY_BASE64","SOURCE_ENTRYPOINT","GITHUB_OUTPUT","GITHUB_ENV","SIGNING_CONFIG","STORAGE_CONFIG","RELEASE_REQUEST","RUSTFLAGS","NODE_OPTIONS"] {assert!(env::var_os(key).is_none(),"{key}");}
        fs::write(Path::new(&args[4]).join("synthetic-ci-observation"),value).unwrap();
        let outputs=Path::new(&args[4]).join("outputs");fs::create_dir(&outputs).unwrap();
        fs::write(outputs.join(format!("ci-private-synthetic-{}",env::var("RELEASE_SOURCE_SHA").unwrap())),b"private synthetic fixture bytes").unwrap();
        println!("private synthetic CI output");
    }"#;
    fs::write(fixture.source.join("tools/release-cli/src/main.rs"), cli).unwrap();
    git(&fixture.source, &["add", "tools/release-cli/src/main.rs"]);
    git(
        &fixture.source,
        &["commit", "-qm", "CI environment fixture"],
    );
    let sha = git(&fixture.source, &["rev-parse", "HEAD"]);
    git(
        &fixture.source,
        &[
            "config",
            "submodule.leapterm-release.url",
            omni_release_launcher::source::PUBLIC_URL,
        ],
    );
    git(
        &fixture.source.join("leapterm-release"),
        &[
            "remote",
            "set-url",
            "origin",
            omni_release_launcher::source::PUBLIC_URL,
        ],
    );
    let request=SourceCiRequest::parse(&json!({"identity":{"source_repository":"omnisolo-llc/leapterm","source_sha":sha,"builder_repository":"omnisolo-llc/leapterm-release","builder_sha":fixture.env["GITHUB_SHA"],"run_id":"42","attempt":"2"},"source_ref":"refs/heads/main","stage":"rust","shard_index":0,"shard_count":1})).unwrap();
    let mut env = fixture.env.clone();
    env.insert(
        "SOURCE_METADATA_READ_TOKEN".into(),
        "synthetic-private-read".into(),
    );
    let root = fixture.runner.join("ci-work");
    fs::create_dir(&root).unwrap();
    let mut log = fs::File::create(root.join("bootstrap.log")).unwrap();
    build_and_dispatch_ci(&fixture.source, &root, &env, &request, &mut log).unwrap();
    let private_name = format!("ci-private-synthetic-{}", request.identity.source_sha);
    assert!(
        root.join("release-work/outputs")
            .join(&private_name)
            .is_file()
    );
    assert!(
        !std::env::current_dir()
            .unwrap()
            .join("release-work/outputs")
            .join(&private_name)
            .exists(),
        "CI dispatch must retain its outputs privately before the authenticated orchestrator's exact receipt handoff"
    );
    let observed = fs::read_to_string(root.join("release-work/synthetic-ci-observation")).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&observed).unwrap(),
        serde_json::to_value(&request).unwrap()
    );
    assert!(
        fs::read_to_string(root.join("bootstrap.log"))
            .unwrap()
            .contains("private synthetic CI output")
    );
    fs::write(
        fixture.source.join("tools/release-cli/src/main.rs"),
        "uncommitted changed source",
    )
    .unwrap();
    let changed = fixture.runner.join("changed-ci-work");
    fs::create_dir(&changed).unwrap();
    let mut log = fs::File::create(changed.join("bootstrap.log")).unwrap();
    assert!(build_and_dispatch_ci(&fixture.source, &changed, &env, &request, &mut log).is_err());
    assert!(
        !changed.join("build-home").exists(),
        "changed source must fail before Cargo starts"
    );
}
#[test]
fn actual_protected_checkout_locked_build_and_dispatch_cover_every_release_target() {
    let fixture = Fixture::new();
    for target in RELEASE_TARGETS {
        let output = fixture.run(
            if *target == "resolve" {
                "resolve"
            } else {
                "run"
            },
            target,
            false,
            false,
        );
        assert!(
            output.status.success(),
            "{target}: {} {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(fixture._temp.path().join("cargo-fixture.log")).unwrap_or_default()
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private synthetic"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-scoped-token"));
        assert_eq!(
            fs::read_dir(&fixture.runner).unwrap().count(),
            0,
            "Checkout and build cleanup: {target}"
        );
    }
    let output = fs::read_to_string(&fixture.env["GITHUB_OUTPUT"]).unwrap();
    assert!(output.contains(&format!("source_sha={}\n", fixture.sha)));
    assert!(output.contains("version=1.2.3\nbuild_number=42\nworkflow_id="));
    for target in omni_release_launcher::input::BUILD_TARGETS {
        assert!(
            fixture.run("run", target, true, false).status.success(),
            "build-only {target}"
        );
    }
    let failure = fixture.run("run", "linux", true, true);
    assert!(!failure.status.success());
    assert!(!String::from_utf8_lossy(&failure.stderr).contains("private synthetic"));
    assert_eq!(fs::read_dir(&fixture.runner).unwrap().count(), 0);
}
#[test]
fn private_task_failure_is_not_misreported_as_native_tool_build_failure() {
    let fixture = Fixture::new();
    let failure = fixture.run("run", "linux", true, true);
    assert!(!failure.status.success());
    let stdout = String::from_utf8_lossy(&failure.stdout);
    let phases: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("Native release phase: "))
        .collect();
    assert_eq!(
        phases,
        [
            "private-checkout",
            "source-check",
            "native-toolchain",
            "native-tool-tests",
            "native-tool-build",
            "private-task"
        ]
    );
    let stderr = String::from_utf8_lossy(&failure.stderr);
    assert!(
        stderr.contains("Private release task failed; native CLI compilation and tests passed")
    );
    assert!(!stderr.contains("Build command failed"));
    assert!(!stdout.contains("private synthetic") && !stderr.contains("private synthetic"));
    assert_eq!(fs::read_dir(&fixture.runner).unwrap().count(), 0);
}

#[test]
fn actual_nonancestor_never_materializes_or_executes_native_source() {
    let mut fixture = Fixture::new();
    let reviewed = fixture.sha.clone();
    fs::write(fixture.source.join("unreviewed"), "must not execute").unwrap();
    git(&fixture.source, &["add", "."]);
    git(&fixture.source, &["commit", "-qm", "unapproved descendant"]);
    fixture.sha = git(&fixture.source, &["rev-parse", "HEAD"]);
    git(&fixture.source, &["checkout", "--detach", "-q", &reviewed]);
    git(&fixture.source, &["branch", "-f", "main", &reviewed]);
    let output = fixture.run("run", "linux", true, false);
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(&fixture.runner).unwrap().count(), 0);
}
#[test]
fn actual_locked_native_agent_dispatch_hands_off_all_six_platform_identities() {
    let fixture = Fixture::new();
    for platform in omni_release_launcher::agent::PLATFORMS {
        let temp = tempfile::tempdir_in(&fixture.runner).unwrap();
        let root = temp.path();
        fs::write(root.join("task.log"), b"").unwrap();
        let mut log = fs::File::create(root.join("bootstrap.log")).unwrap();
        let output = root.join("agent-handoff");
        fs::create_dir(&output).unwrap();
        let mut env = fixture.env.clone();
        env.insert("LEAP_AGENT_PLATFORM".into(), platform.to_string());
        env.insert("LEAP_AGENT_OUTPUT".into(), output.to_str().unwrap().into());
        env.insert(
            "RELEASE_TARGET".into(),
            omni_release_launcher::agent::target(platform)
                .unwrap()
                .into(),
        );
        let request = omni_release_launcher::input::Request::parse(
            &json!({"source_sha":fixture.sha,"build_only":true,"build_number":"1"}).to_string(),
        )
        .unwrap();
        omni_release_launcher::launch::build_and_dispatch(
            &fixture.source,
            root,
            &env,
            &request,
            "agent-run",
            &mut log,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(output.join("synthetic-handoff")).unwrap(),
            *platform
        );
        assert!(
            fs::read_to_string(root.join("bootstrap.log"))
                .unwrap()
                .contains("private synthetic compiler")
        );
    }
}
